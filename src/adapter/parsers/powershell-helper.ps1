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
        # State-invalidating statement semantics. These constructs can change variables, the
        # environment or the working directory, or gate/repeat execution, so any fixed target
        # set derived from the literal command list is not trustworthy. Flag explicitly even
        # when no command node was produced (e.g. a bare `$env:X = 'v'` assignment).
        $assignNodes = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)
        foreach ($a in $assignNodes) {
            $isEnv = $false
            $left = $a.Left
            if ($left -is [System.Management.Automation.Language.ConvertExpressionAst]) { $left = $left.Child }
            if ($left -is [System.Management.Automation.Language.VariableExpressionAst] -and $left.VariablePath.UserPath -imatch '^env:') { $isEnv = $true }
            if ($isEnv) { $unknown.Add('PowerShell environment variable assignment changes state') }
            else { $unknown.Add('PowerShell variable assignment changes state') }
        }
        $loopNodes = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.LoopStatementAst] }, $true)
        foreach ($loop in $loopNodes) { $unknown.Add('PowerShell loop statement repeats execution') }
        $ifNodes = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.IfStatementAst] }, $true)
        foreach ($ifNode in $ifNodes) { $unknown.Add('PowerShell conditional statement gates execution') }
        $tryNodes = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TryStatementAst] }, $true)
        foreach ($tryNode in $tryNodes) { $unknown.Add('PowerShell try/catch statement gates execution') }
        $switchNodes = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.SwitchStatementAst] }, $true)
        foreach ($switchNode in $switchNodes) { $unknown.Add('PowerShell switch statement gates execution') }
        $trapNodes = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TrapStatementAst] }, $true)
        foreach ($trapNode in $trapNodes) { $unknown.Add('PowerShell trap statement installs a handler') }
        # Implicit startup code: `#requires` can auto-import modules/assemblies/snapins at run
        # time (before any command runs). Non-empty requirements are executable and NOT proven
        # by the command list alone. A bare `#requires -Version` gate is benign.
        $req = $ast.ScriptRequirements
        if ($null -ne $req) {
            if ($null -ne $req.RequiredModules -and $req.RequiredModules.Count -gt 0) { $unknown.Add('#requires -Modules auto-imports modules at runtime') }
            if ($null -ne $req.RequiredAssemblies -and $req.RequiredAssemblies.Count -gt 0) { $unknown.Add('#requires -Assembly loads assemblies at runtime') }
            if ($null -ne $req.RequiredPSSnapins -and $req.RequiredPSSnapins.Count -gt 0) { $unknown.Add('#requires -PSSnapin loads snapins at runtime') }
        }
        # `using` statements run module/assembly/namespace resolution before commands execute.
        # Flag EVERY using statement (including `using namespace`) so unnamed startup-time
        # resolution is never silently trusted; nothing is executed here.
        if ($null -ne $ast.UsingStatements -and $ast.UsingStatements.Count -gt 0) {
            $unknown.Add('PowerShell using statement runs module/assembly/namespace resolution at startup')
        }
        # Executable/declarative constructs that can run code or load types but produce no
        # CommandAst (attribute arguments, type/class definitions, type constraints, data
        # blocks, dynamic parameters). Flag conservatively.
        $executableTypes = @(
            'System.Management.Automation.Language.TypeDefinitionAst',
            'System.Management.Automation.Language.FunctionMemberAst',
            'System.Management.Automation.Language.DataStatementAst',
            'System.Management.Automation.Language.DynamicParamBlockAst',
            'System.Management.Automation.Language.AttributeAst',
            'System.Management.Automation.Language.TypeConstraintAst'
        )
        $execNodes = $ast.FindAll({ param($n) $executableTypes -contains $n.GetType().FullName }, $true)
        foreach ($execNode in $execNodes) {
            $typeName = $execNode.GetType().Name
            $unknown.Add("PowerShell $typeName construct can execute or load code")
        }
        # Deduplicate unknown reasons while preserving order.
        $unknownUnique = [Collections.Generic.List[string]]::new()
        $seenUnknown = @{}
        foreach ($reason in $unknown) { if (-not $seenUnknown.ContainsKey($reason)) { $seenUnknown[$reason] = $true; $unknownUnique.Add($reason) } }
        $response = @{ reqId = $request.reqId; commands = @($commands.ToArray()); unknown = @($unknownUnique.ToArray()) }
        [Console]::WriteLine((ConvertTo-Json -InputObject $response -Depth 20 -Compress))
    } catch {
        [Console]::WriteLine((ConvertTo-Json -InputObject @{ reqId = $request.reqId; error = 'PowerShell parser rejected input' } -Compress))
    }
}
