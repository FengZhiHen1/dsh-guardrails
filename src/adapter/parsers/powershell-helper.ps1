$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)

function Get-Literal($Node) {
    if ($Node -is [System.Management.Automation.Language.StringConstantExpressionAst]) { return $Node.Value }
    if ($Node -is [System.Management.Automation.Language.ConstantExpressionAst]) { return [string]$Node.Value }
    if ($Node -is [System.Management.Automation.Language.VariableExpressionAst]) {
        if ($Node.VariablePath.UserPath -ieq 'true') { return '$true' }
        if ($Node.VariablePath.UserPath -ieq 'false') { return '$false' }
    }
    if ($Node -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and $Node.NestedExpressions.Count -eq 0) { return $Node.Value }
    return $null
}

function Add-LiteralArguments($Node, $Arguments) {
    if ($Node -is [System.Management.Automation.Language.ArrayLiteralAst]) {
        foreach ($item in $Node.Elements) { Add-LiteralArguments $item $Arguments }
    } elseif ($Node -is [System.Management.Automation.Language.ArrayExpressionAst]) {
        foreach ($statement in $Node.SubExpression.Statements) {
            if ($statement -is [System.Management.Automation.Language.PipelineAst] -and $statement.PipelineElements.Count -eq 1 -and $statement.PipelineElements[0] -is [System.Management.Automation.Language.CommandExpressionAst]) {
                Add-LiteralArguments $statement.PipelineElements[0].Expression $Arguments
            } else { $Arguments.Add($null) }
        }
    } else { $Arguments.Add((Get-Literal $Node)) }
}

while ($null -ne ($line = [Console]::ReadLine())) {
    try {
        $request = ConvertFrom-Json -InputObject $line
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput([string]$request.source, [ref]$tokens, [ref]$errors)
        if ($errors.Count -gt 0) { throw 'PowerShell syntax error' }
        $commands = [Collections.Generic.List[object]]::new()
        $unknown = [Collections.Generic.List[string]]::new()
        $definitions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
        $functionNames = @($definitions | ForEach-Object { $_.Name })
        $nodes = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -or ($n -is [System.Management.Automation.Language.CommandExpressionAst] -and $n.Redirections.Count -gt 0) }, $true)
        foreach ($node in $nodes) {
            $parent = $node.Parent
            $defined = $false
            $scope = 'script'
            while ($null -ne $parent) {
                if ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $defined = $true; break }
                if ($parent -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) {
                    $owner = $parent.Parent
                    $invoked = $false
                    if ($owner -is [System.Management.Automation.Language.CommandAst]) {
                        $ownerName = $owner.GetCommandName()
                        $invoked = (($owner.CommandElements[0] -eq $parent) -and ([string]$owner.InvocationOperator -in @('Ampersand', 'Dot'))) -or ($ownerName -in @('ForEach-Object', 'Where-Object', 'foreach', 'where', '%', '?', 'Invoke-Command'))
                    }
                    if (-not $invoked) { $defined = $true; break }
                    $scope = 'scriptblock'
                }
                if ($parent -is [System.Management.Automation.Language.SubExpressionAst]) { $scope = 'subexpression' }
                $parent = $parent.Parent
            }
            if ($defined) { continue }
            $elements = @($node.CommandElements)
            $name = $null
            if ($node -is [System.Management.Automation.Language.CommandAst]) { $name = Get-Literal $elements[0] }
            if ($null -ne $name -and $functionNames -contains $name) { $unknown.Add('Invocation of locally defined PowerShell function') }
            $arguments = [Collections.Generic.List[object]]::new()
            for ($i = 1; $i -lt $elements.Count; $i++) {
                $element = $elements[$i]
                if ($element -is [System.Management.Automation.Language.CommandParameterAst]) {
                    $arguments.Add('-' + $element.ParameterName)
                    if ($null -ne $element.Argument) {
                        $literal = Get-Literal $element.Argument
                        if ($literal -in @('$true', '$false')) {
                            $arguments[$arguments.Count - 1] = '-' + $element.ParameterName + ':' + $literal
                        } else { $arguments.Add($literal) }
                    }
                } else { Add-LiteralArguments $element $arguments }
            }
            if ($null -eq $name -or $arguments.Contains($null)) { $unknown.Add('Dynamic command or argument') }
            $redirects = [Collections.Generic.List[object]]::new()
            foreach ($redirect in $node.Redirections) {
                if ($redirect -is [System.Management.Automation.Language.FileRedirectionAst]) {
                    $redirects.Add(@{ operator = $(if ($redirect.Append) { '>>' } else { '>' }); target = (Get-Literal $redirect.Location) })
                } else { $redirects.Add(@{ operator = 'merge'; target = [string]$redirect.ToStream }) }
            }
            $commands.Add(@{ name = $name; args = @($arguments.ToArray()); redirects = @($redirects.ToArray()); scope = $scope })
        }
        # Non-command expression evaluation can invoke methods and constructors.
        $expressions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -or $n -is [System.Management.Automation.Language.TypeExpressionAst] }, $true)
        foreach ($expression in $expressions) {
            $parent = $expression.Parent
            $defined = $false
            while ($null -ne $parent) {
                if ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $defined = $true; break }
                $parent = $parent.Parent
            }
            if (-not $defined) { $unknown.Add('PowerShell member/type expression'); break }
        }
        $response = @{ reqId = $request.reqId; commands = @($commands.ToArray()); unknown = @($unknown.ToArray()) }
        [Console]::WriteLine((ConvertTo-Json -InputObject $response -Depth 20 -Compress))
    } catch {
        [Console]::WriteLine((ConvertTo-Json -InputObject @{ reqId = $request.reqId; error = 'PowerShell parser rejected input' } -Compress))
    }
}
