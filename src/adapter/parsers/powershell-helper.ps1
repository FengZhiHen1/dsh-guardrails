$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)

# A literal value that does not consult any variable (used to build the constant map).
function Get-StaticLiteral($Node) {
    if ($null -eq $Node) { return $null }
    if ($Node -is [System.Management.Automation.Language.StringConstantExpressionAst]) { return $Node.Value }
    if ($Node -is [System.Management.Automation.Language.ConstantExpressionAst]) { return [string]$Node.Value }
    if ($Node -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and $Node.NestedExpressions.Count -eq 0) { return $Node.Value }
    return $null
}

# An assignment's Right is a statement (usually a PipelineAst wrapping a CommandExpression);
# unwrap that to inspect the actual value expression.
function Get-AssignmentStaticValue($Right) {
    $expression = $Right
    if ($null -eq $expression) { return $null }
    if ($expression -is [System.Management.Automation.Language.CommandExpressionAst]) {
        $expression = $expression.Expression
    } elseif ($expression -is [System.Management.Automation.Language.PipelineAst]) {
        if ($expression.PipelineElements.Count -ne 1) { return $null }
        $element = $expression.PipelineElements[0]
        if (-not ($element -is [System.Management.Automation.Language.CommandExpressionAst])) { return $null }
        $expression = $element.Expression
    }
    return Get-StaticLiteral $expression
}

# Bounded single-assignment literal variables for the current request. Only a top-level
# variable assigned exactly once to a static literal, before the use site, is resolved; a
# re-assigned or non-literal variable stays dynamic (fail-closed). This recovers the common
# `$p = 'literal-path'; ... -LiteralPath $p` shape without guessing.
$script:literalVars = @{}

function Get-Literal($Node) {
    if ($null -eq $Node) { return $null }
    if ($Node -is [System.Management.Automation.Language.StringConstantExpressionAst]) { return $Node.Value }
    if ($Node -is [System.Management.Automation.Language.ConstantExpressionAst]) { return [string]$Node.Value }
    if ($Node -is [System.Management.Automation.Language.VariableExpressionAst]) {
        $userPath = $Node.VariablePath.UserPath
        if ($userPath -ieq 'true') { return '$true' }
        if ($userPath -ieq 'false') { return '$false' }
        $entry = $script:literalVars[$userPath]
        if ($null -ne $entry -and $entry.Offset -lt $Node.Extent.StartOffset) { return $entry.Value }
        return $null
    }
    if ($Node -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and $Node.NestedExpressions.Count -eq 0) { return $Node.Value }
    return $null
}

# Render the offending source span for a diagnostic (single line, bounded to 120 chars).
function Format-Extent($Node) {
    if ($null -eq $Node -or $null -eq $Node.Extent) { return '' }
    $text = [string]$Node.Extent.Text
    $text = ($text -replace '\s+', ' ').Trim()
    if ($text.Length -gt 120) { $text = $text.Substring(0, 120) + '...' }
    return $text
}

# Add a diagnostic with the offending expression appended (keeps the category prefix).
function Add-Unknown($List, $Message, $Node) {
    $text = Format-Extent $Node
    if ([string]::IsNullOrEmpty($text)) { $List.Add($Message) } else { $List.Add($Message + ': ' + $text) }
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

# Bounded display text for ONE upstream PipelineElements entry (DSR-031 decision 9).
# Only provable pieces are rendered: the literal command name plus literal arguments
# (parameter names are literal by the AST; a parameter value is rendered only when it
# resolves to a literal, and a `$true`/`$false` value keeps the `-Name:value` token
# shape used for arguments). A non-command element, a dynamic command name, or an
# argument that cannot be proven are omitted rather than guessed. The result is a
# human scope label, never a path or a predicate; it is bounded like Format-Extent.
function Format-PipelineSource($Element) {
    if ($null -eq $Element -or -not ($Element -is [System.Management.Automation.Language.CommandAst])) { return $null }
    $elements = @($Element.CommandElements)
    if ($elements.Count -eq 0) { return $null }
    $name = Get-Literal $elements[0]
    if ($null -eq $name) { return $null }
    $parts = [Collections.Generic.List[string]]::new()
    $parts.Add([string]$name)
    for ($i = 1; $i -lt $elements.Count; $i++) {
        $element = $elements[$i]
        if ($element -is [System.Management.Automation.Language.CommandParameterAst]) {
            $token = '-' + $element.ParameterName
            $literal = if ($null -ne $element.Argument) { Get-Literal $element.Argument } else { $null }
            if ($null -eq $literal) { $parts.Add($token) }
            elseif ($literal -in @('$true', '$false')) { $parts.Add($token + ':' + $literal) }
            else { $parts.Add($token); $parts.Add([string]$literal) }
        } else {
            $literal = Get-Literal $element
            if ($null -ne $literal) { $parts.Add([string]$literal) }
        }
    }
    $text = ($parts.ToArray() -join ' ')
    $text = ($text -replace '\s+', ' ').Trim()
    if ([string]::IsNullOrEmpty($text)) { return $null }
    if ($text.Length -gt 120) { $text = $text.Substring(0, 120) + '...' }
    return $text
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
        # Build the bounded literal-variable map for THIS request (see Get-Literal).
        $script:literalVars = @{}
        $assignCounts = @{}
        $literalCandidates = @{}
        $allAssignments = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)
        foreach ($assignment in $allAssignments) {
            $left = $assignment.Left
            if ($left -is [System.Management.Automation.Language.ConvertExpressionAst]) { continue } # typed assignment: skip mapping
            if (-not ($left -is [System.Management.Automation.Language.VariableExpressionAst])) { continue }
            $varPath = $left.VariablePath.UserPath
            if ($varPath -imatch '^env:') { continue } # environment variables are not constant
            # Only straight-line top-level assignments are trusted.
            $blocked = $false
            $ancestor = $assignment.Parent
            while ($null -ne $ancestor) {
                if ($ancestor -is [System.Management.Automation.Language.FunctionDefinitionAst] -or
                    $ancestor -is [System.Management.Automation.Language.ScriptBlockExpressionAst] -or
                    $ancestor -is [System.Management.Automation.Language.LoopStatementAst] -or
                    $ancestor -is [System.Management.Automation.Language.IfStatementAst] -or
                    $ancestor -is [System.Management.Automation.Language.SwitchStatementAst] -or
                    $ancestor -is [System.Management.Automation.Language.TryStatementAst]) { $blocked = $true; break }
                $ancestor = $ancestor.Parent
            }
            if ($blocked) { continue }
            $assignCounts[$varPath] = 1 + [int]($assignCounts[$varPath])
            $staticValue = Get-AssignmentStaticValue $assignment.Right
            if ($null -ne $staticValue) { $literalCandidates[$varPath] = @{ Value = $staticValue; Offset = $assignment.Extent.EndOffset } }
        }
        foreach ($varPath in @($literalCandidates.Keys)) {
            if ([int]($assignCounts[$varPath]) -eq 1) { $script:literalVars[$varPath] = $literalCandidates[$varPath] }
        }
        $definitions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
        $functionNames = @($definitions | ForEach-Object { $_.Name })
        $nodes = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -or ($n -is [System.Management.Automation.Language.CommandExpressionAst] -and $n.Redirections.Count -gt 0) }, $true)
        # pipeline -> (element -> index) map, built once per PipelineAst. This keeps
        # pipelineIndex lookup linear overall instead of rescanning each pipeline.
        $pipelinePositions = @{}
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
            if ($null -ne $name -and $functionNames -contains $name) { Add-Unknown $unknown 'Invocation of locally defined PowerShell function' $node }
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
            # A null command NAME is an execution channel (unknown). A null ARGUMENT is not
            # flagged here: each grammar (delete/move/read) decides it; a delete with a
            # dynamic operand is denied by deletion-intent, not by this parser diagnostic.
            if ($null -eq $name) { Add-Unknown $unknown 'Dynamic command or argument' $node }
            $redirects = [Collections.Generic.List[object]]::new()
            foreach ($redirect in $node.Redirections) {
                if ($redirect -is [System.Management.Automation.Language.FileRedirectionAst]) {
                    $redirects.Add(@{ operator = $(if ($redirect.Append) { '>>' } else { '>' }); target = (Get-Literal $redirect.Location) })
                } else { $redirects.Add(@{ operator = 'merge'; target = [string]$redirect.ToStream }) }
            }
            # Pipeline position (DSR-031 decision 9): the 0-based slot of this node in
            # its nearest PipelineAst plus the bounded text of the immediately
            # preceding element. `pipelineIndex` is always present (a single-element
            # pipeline is 0); `pipelineSource` exists only for index > 0 and is $null
            # when that upstream element is an expression or otherwise not provable.
            $pipelineIndex = 0
            $pipelineSource = $null
            $pipeline = $node.Parent
            while ($null -ne $pipeline -and -not ($pipeline -is [System.Management.Automation.Language.PipelineAst])) { $pipeline = $pipeline.Parent }
            if ($null -ne $pipeline) {
                $positions = $pipelinePositions[$pipeline]
                if ($null -eq $positions) {
                    $positions = @{}
                    for ($position = 0; $position -lt $pipeline.PipelineElements.Count; $position++) {
                        $positions[$pipeline.PipelineElements[$position]] = $position
                    }
                    $pipelinePositions[$pipeline] = $positions
                }
                if ($positions.ContainsKey($node)) { $pipelineIndex = [int]$positions[$node] }
                if ($pipelineIndex -gt 0) { $pipelineSource = Format-PipelineSource $pipeline.PipelineElements[$pipelineIndex - 1] }
            }
            $command = @{ name = $name; args = @($arguments.ToArray()); redirects = @($redirects.ToArray()); scope = $scope; pipelineIndex = $pipelineIndex }
            if ($pipelineIndex -gt 0) { $command['pipelineSource'] = $pipelineSource }
            $commands.Add($command)
        }
        # Non-command expression evaluation can invoke methods and constructors. Grade by
        # capability: property/index access is not in this scan at all; pure string/format
        # instance methods on a variable/property/string target are allowed; every static
        # type member call and every other method stays an explicit unknown. Nothing is run.
        $stringMethodWhitelist = @('replace', 'substring', 'trim', 'trimstart', 'trimend', 'toupper', 'tolower', 'tostring', 'padleft', 'padright', 'split', 'indexof', 'lastindexof', 'startswith', 'endswith', 'contains', 'normalize')
        $expressions = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -or $n -is [System.Management.Automation.Language.TypeExpressionAst] }, $true)
        foreach ($expression in $expressions) {
            $parent = $expression.Parent
            $defined = $false
            while ($null -ne $parent) {
                if ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $defined = $true; break }
                $parent = $parent.Parent
            }
            if ($defined) { continue }
            if ($expression -is [System.Management.Automation.Language.TypeExpressionAst]) {
                # A type expression that is the target of a static member call is handled by
                # the InvokeMember branch below (so it carries the member detail); a bare type
                # expression (cast) cannot be proven free of conversion side effects.
                if ($expression.Parent -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) { continue }
                Add-Unknown $unknown 'PowerShell member/type expression' $expression
                continue
            }
            $target = $expression.Expression
            $isStatic = $target -is [System.Management.Automation.Language.TypeExpressionAst]
            $memberName = $null
            if ($expression.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $memberName = $expression.Member.Value }
            $allowedTarget = ($target -is [System.Management.Automation.Language.VariableExpressionAst]) -or
                ($target -is [System.Management.Automation.Language.MemberExpressionAst]) -or
                ($target -is [System.Management.Automation.Language.StringConstantExpressionAst]) -or
                ($target -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) -or
                (($target -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) -and ($target.NestedExpressions.Count -eq 0))
            # Whitelist applies ONLY to instance methods on a variable/property/string target.
            # A static type call ([IO.File]::Delete) or an uncertain target is always refused.
            if ((-not $isStatic) -and $allowedTarget -and $null -ne $memberName -and ($stringMethodWhitelist -contains $memberName.ToLower())) { continue }
            Add-Unknown $unknown 'PowerShell member/type expression' $expression
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
            if ($isEnv) { Add-Unknown $unknown 'PowerShell environment variable assignment changes state' $a }
            else { Add-Unknown $unknown 'PowerShell variable assignment changes state' $a }
        }
        $loopNodes = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.LoopStatementAst] }, $true)
        foreach ($loop in $loopNodes) { Add-Unknown $unknown 'PowerShell loop statement repeats execution' $loop }
        $ifNodes = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.IfStatementAst] }, $true)
        foreach ($ifNode in $ifNodes) { Add-Unknown $unknown 'PowerShell conditional statement gates execution' $ifNode }
        $tryNodes = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TryStatementAst] }, $true)
        foreach ($tryNode in $tryNodes) { Add-Unknown $unknown 'PowerShell try/catch statement gates execution' $tryNode }
        $switchNodes = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.SwitchStatementAst] }, $true)
        foreach ($switchNode in $switchNodes) { Add-Unknown $unknown 'PowerShell switch statement gates execution' $switchNode }
        $trapNodes = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TrapStatementAst] }, $true)
        foreach ($trapNode in $trapNodes) { Add-Unknown $unknown 'PowerShell trap statement installs a handler' $trapNode }
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
        # CommandAst (attribute arguments, type/class definitions, data blocks, dynamic
        # parameters). Flag conservatively. TypeConstraintAst is handled separately below.
        $executableTypes = @(
            'System.Management.Automation.Language.TypeDefinitionAst',
            'System.Management.Automation.Language.FunctionMemberAst',
            'System.Management.Automation.Language.DataStatementAst',
            'System.Management.Automation.Language.DynamicParamBlockAst',
            'System.Management.Automation.Language.AttributeAst'
        )
        $execNodes = $ast.FindAll({ param($n) $executableTypes -contains $n.GetType().FullName }, $true)
        foreach ($execNode in $execNodes) {
            $typeName = $execNode.GetType().Name
            Add-Unknown $unknown "PowerShell $typeName construct can execute or load code" $execNode
        }
        # TypeConstraintAst is a pure conversion/declaration for the BUILT-IN primitive types
        # (e.g. [int]$x = 3); those are allowed. A custom/unknown type constraint may run a
        # type converter/initializer and stays unknown. Static `::` member calls are refused
        # by the InvokeMember/TypeExpression branch above, independent of this.
        $primitiveTypes = @(
            'int', 'int16', 'int32', 'int64', 'uint16', 'uint32', 'uint64', 'byte', 'sbyte', 'short', 'ushort', 'long', 'ulong',
            'single', 'float', 'double', 'decimal', 'bool', 'boolean', 'string', 'char', 'object', 'void', 'guid', 'datetime', 'timespan', 'intptr', 'uintptr',
            'system.int16', 'system.int32', 'system.int64', 'system.uint16', 'system.uint32', 'system.uint64', 'system.byte', 'system.sbyte',
            'system.single', 'system.double', 'system.decimal', 'system.boolean', 'system.string', 'system.char', 'system.object', 'system.void',
            'system.guid', 'system.datetime', 'system.timespan', 'system.intptr', 'system.uintptr'
        )
        $constraintNodes = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TypeConstraintAst] }, $true)
        foreach ($constraintNode in $constraintNodes) {
            $typeFullName = ''
            if ($null -ne $constraintNode.TypeName) {
                $typeFullName = [string]$constraintNode.TypeName.FullName
                if ([string]::IsNullOrEmpty($typeFullName)) { $typeFullName = [string]$constraintNode.TypeName.Name }
            }
            if ($primitiveTypes -contains $typeFullName.ToLower()) { continue }
            Add-Unknown $unknown 'PowerShell TypeConstraintAst construct can execute or load code' $constraintNode
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
