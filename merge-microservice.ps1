######################################################################
#
# This script merges applications into master applications defined by application metadata fields
#
#   @author   prashant.mishra@contrastsecurity.com
#   @author   sergei.bulatov@contrastsecurity.com
#   @author   david.mullally@contrastsecurity.com
#
#####################################################################

param (
    [switch]$force = $false,
    [switch]$createmasterapp = $false
)

# ===================================================================
# Variables. Edit for your Connection Details as per TS.
# ===================================================================

$CONTRAST_API_URL = "https://apptwo.contrastsecurity.com/Contrast/api/ng"
$CONTRAST_AUTH_TOKEN = 'AUTH'
$CONTRAST_API_KEY = 'API_KEY'
$CONTRAST_ORG_ID = 'ORG_ID'

function Add-Log( $MESSAGE, $FILE, $APPEND ) {
    $TIMESTAMP = "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    if ( $APPEND -eq "Create" ) {
        Write-Output "$TIMESTAMP $MESSAGE" | Out-file $FILE 
    }
    else {
        Write-Output "$TIMESTAMP $MESSAGE" | Out-file $FILE -Append
    }
    Write-Host $MESSAGE | Out-Null
}

function New-Dir-If-Not-Exist ($DIR ) {
    if (!(Test-Path -Path $DIR)) {
        New-Item -ItemType Directory -Force -Path $DIR
    }
}

function Get-Current-Time( ) {
    $DATE = (Get-Date)
    $YEAR = $DATE.Year
    $MONTH = $DATE.MONTH
    $DAY = $DATE.DAY
    $HOUR = $DATE.Hour
    $MINUTE = $DATE.Minute
    return "$YEAR$MONTH$DAY-$HOUR-$MINUTE"
}

function Get-Groups-For-Org($CONTRAST_API_URL, $CONTRAST_ORG_ID, $CONTRAST_AUTH_TOKEN, $CONTRAST_API_KEY, $INDEX, $LIMIT) {
    $GROUPS = @()
    $RESPONSE_GROUP_LIST = Invoke-RestMethod "$CONTRAST_API_URL/$CONTRAST_ORG_ID/groups?expand=users,applications,skip_links&quickFilter=ALL&sort=name&offset=$INDEX&limit=$LIMIT" -Method GET -ContentType "application/json" -Headers @{"Authorization" = "$CONTRAST_AUTH_TOKEN"; "API-Key" = "$CONTRAST_API_KEY" } 

    if ( $RESPONSE_GROUP_LIST.success ) {
        Add-Log "$DRY_RUN Ognization groups details fetched successfully from $INDEX to $LIMIT." $LOG_FILE
        
        if (($INDEX + $LIMIT) -le $RESPONSE_GROUP_LIST.custom_groups.count) {
            $GROUPS += Get-Groups-For-Org $CONTRAST_API_URL $CONTRAST_ORG_ID $CONTRAST_AUTH_TOKEN $CONTRAST_API_KEY ($INDEX + $LIMIT) $LIMIT
        }
        else {
            return $RESPONSE_GROUP_LIST.custom_groups.groups
        }

        $GROUPS += $RESPONSE_GROUP_LIST.custom_groups.groups
        return $GROUPS
    }
}

function Get-App-Group-Map ($GROUPS) {
    $APP_NAME_GROUP_MAP = @{}

    $GROUPS | ForEach-Object -Process {
        $GROUP = $_
        $GROUP.applications | ForEach-Object -Process {
            if ($null -ne $_.application) {
                if ($APP_NAME_GROUP_MAP.ContainsKey($_.application.name) -eq $FALSE) {
                    $GROUP_SET = New-Object System.Collections.Generic.HashSet[string]
                    $APP_NAME_GROUP_MAP.Add($_.application.name, $GROUP_SET)
                }
                $APP_NAME_GROUP_MAP[$_.application.name].Add($GROUP.name) | out-null
            } 
        }
    }
    return $APP_NAME_GROUP_MAP
}

function Get-App-List-For-Org($CONTRAST_API_URL, $CONTRAST_ORG_ID, $CONTRAST_AUTH_TOKEN, $CONTRAST_API_KEY, $INDEX, $LIMIT) {
    $APPLICATIONS = @()
    $APP_URL = "$CONTRAST_API_URL/$CONTRAST_ORG_ID/applications/filter?expand=trace_severity_breakdown&offset=$INDEX&limit=$LIMIT&includeMerged=true"
    $RESPONSE_APP_LIST = Invoke-RestMethod $APP_URL -Method GET -ContentType "application/json" -Headers @{"Authorization" = "$CONTRAST_AUTH_TOKEN"; "API-Key" = "$CONTRAST_API_KEY" } 

    if ( $RESPONSE_APP_LIST.success ) {
        Add-Log "$DRY_RUN Ognization applications details fetched successfully from $INDEX to $LIMIT." $LOG_FILE
        Write-Host "$DRY_RUN Ognization applications details fetched successfully from $INDEX to $LIMIT."
        if (($INDEX + $LIMIT) -le $RESPONSE_APP_LIST.count) {
            $APPS = Get-App-List-For-Org $CONTRAST_API_URL $CONTRAST_ORG_ID $CONTRAST_AUTH_TOKEN $CONTRAST_API_KEY ($INDEX + $LIMIT) $LIMIT
            $APPLICATIONS += $APPS
        }
        else {
            return $RESPONSE_APP_LIST.applications
        }

        $APPLICATIONS += $RESPONSE_APP_LIST.applications
        return $APPLICATIONS
    }
}

function Get-Apps-Filtered-On-Merged-Status {
    param (
        $APP_LIST,
        $MERGED_STATUS
    )
    $FILTERED_APPS = @()
    
    $APP_LIST | ForEach-Object -Process {
        if ($MERGED_STATUS -eq $_.primary) {
            $FILTERED_APPS += $_
        }
    }
    return $FILTERED_APPS
}
function Get-App-Name-APP_ID-MAP ($APP_LIST) {
    $APP_NAME_APP_ID_MAP = @{}
    
    $APP_LIST | ForEach-Object -Process {
        $APP_NAME_APP_ID_MAP.Add($_.name, $_.app_id) | out-null
    }
    return $APP_NAME_APP_ID_MAP
}

function Get-App-Metadata-Value($CONTRAST_API_URL, $CONTRAST_ORG_ID, $CONTRAST_AUTH_TOKEN, $CONTRAST_API_KEY, $APP_ID, $METADATA_FIELD_NAME) {
    $METADATA_VALUE = $null
    $METADATA_URL = "$CONTRAST_API_URL/$CONTRAST_ORG_ID/applications/$APP_ID`?expand=metadata,skip_links"
    $RESPONSE_METADATA = Invoke-RestMethod "$METADATA_URL" -Method GET -ContentType "application/json" -Headers @{"Authorization" = "$CONTRAST_AUTH_TOKEN"; "API-Key" = "$CONTRAST_API_KEY" } 
    if ($RESPONSE_METADATA.success -and $RESPONSE_METADATA.application.missingRequiredFields.Length -eq 0 ) { 
        $RESPONSE_METADATA.application.metadataEntities | ForEach-Object -Process {
            if ($_.fieldName -eq $METADATA_FIELD_NAME) {
                $METADATA_VALUE = $_.fieldValue -replace ",", ""
                $METADATA_VALUE -replace " ", ""
            }
        }
    }
    else {
        Add-Log "$DRY_RUN $APP_ID Missing Metadata: $METADATA_FIELD_NAME" $LOG_FILE
            
    }
    return $METADATA_VALUE
}
function Get-Metadata-App-Map($CONTRAST_API_URL, $CONTRAST_ORG_ID, $CONTRAST_AUTH_TOKEN, $CONTRAST_API_KEY, $APP_LIST, $METADATA_FIELD_NAME) {
    $PARENT_CHILD_APP_MAP = @{}
    $APP_LIST | ForEach-Object -Process {
        $APP_NAME = $_.name
        Add-Log "$DRY_RUN Fetching metadata for $APP_NAME" $LOG_FILE
        $METADATA_VALUE = Get-App-Metadata-Value $CONTRAST_API_URL $CONTRAST_ORG_ID $CONTRAST_AUTH_TOKEN $CONTRAST_API_KEY $_.app_id $METADATA_FIELD_NAME
        if ($null -ne $METADATA_VALUE) {
            if ($PARENT_CHILD_APP_MAP.ContainsKey($METADATA_VALUE) -eq $FALSE) {
                $APP_SET = New-Object System.Collections.Generic.HashSet[string]
                $PARENT_CHILD_APP_MAP.Add($METADATA_VALUE, $APP_SET)
            }
            $PARENT_CHILD_APP_MAP[$METADATA_VALUE].Add($APP_NAME) | out-null
        }
    }
    return $PARENT_CHILD_APP_MAP
}

function Get-Parent-Apps-Already-In-Contrast  ($PARENT_CHILD_APP_MAP, $APP_NAME_APP_ID_MAP) {
    $PARENT_NAME_ALREADY_IN_CONTRAST = @{}
    foreach ($KEY in $PARENT_CHILD_APP_MAP.Keys) {
        if ($true -eq $APP_NAME_APP_ID_MAP.Contains($KEY)) {
            Add-Log "$DRY_RUN $KEY found in Contrast Team Server" $LOG_FILE
            $PARENT_NAME_ALREADY_IN_CONTRAST.Add($KEY, $PARENT_CHILD_APP_MAP[$KEY]) 
        }
    }
    return $PARENT_NAME_ALREADY_IN_CONTRAST
}

function Get-Parent-App-Groups {
    Param(
        $MERGED_APPS,
        $APP_NAME_GROUP_MAP
    )
    $GROUPS = New-Object System.Collections.Generic.HashSet[string]
    foreach ($APP in $MERGED_APPS) {
        $APP_NAME_GROUP_MAP[$APP] | ForEach-Object -Process { $GROUPS.Add($_) } | Out-Null
    }

    Add-Log "$DRY_RUN $PARENT_APP application will be added to groups $GROUPS..." $LOG_FILE | Out-Null
    return $GROUPS
}

function Get-Parent-App-Language{
    param(
        $CHILD_APPS,
        $APP_NAME_LANGUAGE_MAP
    )
    $APP_LANGUAGE = $null
    $MAX_COMMON_LANG_COUNT = 0
    $LANGUAGE_COUNT_MAP = @{}
    foreach($APP in $CHILD_APPS){
        $LANGUAGE = $APP_NAME_LANGUAGE_MAP[$APP]
        if($false -eq $LANGUAGE_COUNT_MAP.ContainsKey($LANGUAGE)){
            $LANGUAGE_COUNT_MAP.Add($LANGUAGE, 1)
        }else{
            $LANGUAGE_COUNT_MAP[$LANGUAGE] += 1
        }
    }
    foreach ($LANG in $LANGUAGE_COUNT_MAP.Keys) {
        if($LANGUAGE_COUNT_MAP[$LANG] -gt $MAX_COMMON_LANG_COUNT){
            $MAX_COMMON_LANG_COUNT = $LANGUAGE_COUNT_MAP[$LANG]
            $APP_LANGUAGE = $LANG
        }
    }
    
    Add-Log "$DRY_RUN $PARENT_APP application will created with language $APP_LANGUAGE..." $LOG_FILE

    return $APP_LANGUAGE
}
function Add-Parent-Apps-To-Contrast {
    param (
        $CONTRAST_API_URL,
        $CONTRAST_ORG_ID,
        $CONTRAST_AUTH_TOKEN,
        $CONTRAST_API_KEY,
        $PARENT_APPS_NOT_CONTRAST,
        $APP_NAME_GROUP_MAP,
        $APP_NAME_LANGUAGE_MAP,
        $APP_NAME_APP_ID_MAP
    )
    foreach ($PARENT_APP in $PARENT_APPS_NOT_CONTRAST.keys) {
        Add-Log "$DRY_RUN Processing $PARENT_APP..." $LOG_FILE
        Add-Log "$DRY_RUN Gettig application group for $PARENT_APP..." $LOG_FILE
        $PARENT_APP_GROUPS = Get-Parent-App-Groups $PARENT_APPS_NOT_CONTRAST[$PARENT_APP] $APP_NAME_GROUP_MAP
        Add-Log "$DRY_RUN Getting application language for $PARENT_APP..." $LOG_FILE
        $PARENT_APP_LANGUAGE = Get-Parent-App-Language $PARENT_APPS_NOT_CONTRAST[$PARENT_APP] $APP_NAME_LANGUAGE_MAP
        Add-Log "$DRY_RUN Creating a container application as $PARENT_APP..." $LOG_FILE
        $CREATED_APP = Add-Empty-App-With-Group $CONTRAST_API_URL $CONTRAST_ORG_ID $CONTRAST_AUTH_TOKEN $CONTRAST_API_KEY $PARENT_APP $PARENT_APP_GROUPS $PARENT_APP_LANGUAGE
        $PARENT_APP_ID = $CREATED_APP.app_id
        $CHILD_APP_IDS = @()
        $CHILD_APP_IDS += Get-Child-App-Ids $PARENT_APPS_NOT_CONTRAST[$PARENT_APP] $APP_NAME_APP_ID_MAP
        Add-Log "$DRY_RUN Adding child apps to container application $PARENT_APP..." $LOG_FILE
        Add-Apps-To-Parent-App $CONTRAST_API_URL $CONTRAST_ORG_ID $CONTRAST_AUTH_TOKEN $CONTRAST_API_KEY $PARENT_APP_ID $CHILD_APP_IDS $PARENT_APPS_NOT_CONTRAST[$PARENT_APP] | Out-Null
    }
}


function Add-Child-Apps-To-Parent{
    param(
        $CONTRAST_API_URL,
        $CONTRAST_ORG_ID,
        $CONTRAST_AUTH_TOKEN,
        $CONTRAST_API_KEY,
        $PARENT_APPS_ALREADY_CONTRAST,
        $MERGED_APPS,
        $UNMERGED_APPS,
        $APP_NAME_APP_ID_MAP
    )
    $UNMERGED_APP_NAMES = @()
    foreach($APPS in $UNMERGED_APPS){
        if($false -eq ($APPS.PSobject.Properties.name -match "ParentApplication")){
            $UNMERGED_APP_NAMES += $APPS.name
        }
    }

    foreach ($PARENT_APP_NAME in $PARENT_APPS_ALREADY_CONTRAST.keys) {
        $PARENT_APP = $MERGED_APPS | Where-Object -FilterScript { $_.name -eq $PARENT_APP_NAME}
        if($null -ne $PARENT_APP){
            $PARENT_APP_ID = $PARENT_APP.app_id
            $CHILD_APP_IDS = @()
            $CHILD_APP_NAMES = $PARENT_APPS_ALREADY_CONTRAST[$PARENT_APP_NAME] | Where-Object -FilterScript{ $UNMERGED_APP_NAMES.Contains($_)}
            if($null -ne $CHILD_APP_NAMES -and $CHILD_APP_NAMES.Count -gt 0){
                $CHILD_APP_IDS += Get-Child-App-Ids $CHILD_APP_NAMES $APP_NAME_APP_ID_MAP
                Add-Apps-To-Parent-App $CONTRAST_API_URL $CONTRAST_ORG_ID $CONTRAST_AUTH_TOKEN $CONTRAST_API_KEY $PARENT_APP_ID $CHILD_APP_IDS $CHILD_APP_NAMES | Out-Null
            }else{
                Add-Log "$DRY_RUN All apps are already merged for $PARENT_APP_NAME" $LOG_FILE
            }
        }else {
            Add-Log "$DRY_RUN $PARENT_APP_NAME already exist and not a parent application, please make sure if this app is following CVS naming standard" $LOG_FILE
        }
        
    }
}
function Add-Apps-To-Parent-App {
    param(
        $CONTRAST_API_URL,
        $CONTRAST_ORG_ID,
        $CONTRAST_AUTH_TOKEN,
        $CONTRAST_API_KEY,
        $PARENT_APP_ID,
        $CHILD_APP_IDS,
        $CHILD_APP_NAMES
    )

    $RESULT = $false
    $APP_NAMES = [string]::Join(",", $CHILD_APP_NAMES)

    if($DRY_RUN){
        Add-Log "$DRY_RUN $APP_NAMES merged with master app $PARENT_APP_ID successfully" $LOG_FILE
        return $true
    }

    $MERGE_URL = "$CONTRAST_API_URL/$CONTRAST_ORG_ID/modules/$PARENT_APP_ID/merge"
    $MERGE_REQUEST_BODY = @{
            apps = $CHILD_APP_IDS
        }
    $MERGE_REQUEST_BODY_JSON = ConvertTo-Json $MERGE_REQUEST_BODY
    try {
    $MERGE_APP_UPDATE = Invoke-RestMethod "$MERGE_URL" -Method PUT -ContentType "application/json" -Headers @{"Authorization" = "$CONTRAST_AUTH_TOKEN"; "API-Key" = "$CONTRAST_API_KEY"; "Content-type" = "application/json" } -Body $MERGE_REQUEST_BODY_JSON
    }
    catch {
    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
    Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
    }
    if ($MERGE_APP_UPDATE.success) {
        Add-Log "$DRY_RUN $APP_NAMES merged with master app $PARENT_APP_ID successfully" $LOG_FILE
        $RESULT = $true
    }
    else {
        Add-Log "$DRY_RUN ERROR while merging $APP_NAMES with master app $PARENT_APP_ID" $LOG_FILE
        Add-Log "$DRY_RUN $MERGE_APP_UPDATE" $LOG_FILE
    }
    return $RESULT
}
function Add-Empty-App-With-Group {
    param(
        $CONTRAST_API_URL,
        $CONTRAST_ORG_ID,
        $CONTRAST_AUTH_TOKEN,
        $CONTRAST_API_KEY,
        $APP_NAME,
        $APP_GROUPS,
        $APP_LANGUAGE
    )

    if($DRY_RUN){
        Add-Log "$DRY_RUN Successfully created master app $APP_NAME" $LOG_FILE
        return @{app_id="dryrun-application-id"}
    }

    $CREATED_APP = $null
    $APP_GROUPS_CSV = [string]::Join(",", $APP_GROUPS)
    $APP_CREATE_URL = "$CONTRAST_API_URL/sca/organizations/$CONTRAST_ORG_ID/applications/create"
    $CREATE_APP_BODY = @{
        name      = $APP_NAME
        language  = $APP_LANGUAGE.toUpper()
        appGroups = $APP_GROUPS_CSV
    }
    $CREATE_APP_BODY_JSON = $CREATE_APP_BODY | ConvertTo-Json
    try {
    $CREATE_APP_UPDATE = Invoke-RestMethod "$APP_CREATE_URL" -Method POST -ContentType "application/json" -Headers @{"Authorization" = "$CONTRAST_AUTH_TOKEN"; "API-Key" = "$CONTRAST_API_KEY"; "Content-type" = "application/json" } -Body $CREATE_APP_BODY_JSON
    } 
    catch {
    Write-Host "StatusCode:" $_.Exception.Response.StatusCode.value__ 
    Write-Host "StatusDescription:" $_.Exception.Response.StatusDescription
    }

    if ($CREATE_APP_UPDATE.success) {
        Add-Log "$DRY_RUN Successfully created master app $APP_NAME" $LOG_FILE
        $CREATED_APP = $CREATE_APP_UPDATE.application
    }
    else {
        Add-Log "$DRY_RUN ERROR while creating master app $APP_NAME" $LOG_FILE
        Add-Log "$DRY_RUN $CREATE_APP_UPDATE" $LOG_FILE
    }
    return $CREATED_APP
}

function Get-Child-App-Ids {
    param(
        $CHILD_APP_NAMES,
        $APP_NAME_APP_ID_MAP
    )
    $APP_IDS = @()

    foreach ($APP in $CHILD_APP_NAMES) {
        $APP_IDS = $APP_NAME_APP_ID_MAP[$APP]
    }

    return $APP_IDS
}

$PSDefaultParameterValues['Invoke-RestMethod:SkipHeaderValidation'] = $true
$DRY_RUN = ""
if ($force) {
    Write-Output "Force set"
}
else {
    $DRY_RUN = "[Dry Run]:"
}

if ($createmasterapp) {
    Write-Output "$DRY_RUN Master app will be created if it does not exist!"
}

$COMMAND_NAME = $MyInvocation.MyCommand.Name
$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$LOG_DIR = "$scriptPath/logs"
$REPORT_DIR = "$scriptPath/reports"
New-Dir-If-Not-Exist($LOG_DIR)
New-Dir-If-Not-Exist($REPORT_DIR)

if ( $args.Count -eq 0 -or $args.Count -gt 3 ) {
    Write-Output "This script merges all microservices that have application metadata specified field, into the application with name specified by the value of the field. "
    Write-Output "If this application does not exist, it will be created. It expects the following inputs:"
    Write-Output "   - Application Metadata Field : Name of application metadata field to use for the name of the application to merge into"
    Write-Output "   -force : Will force script to create app(s) and merge apps (if needed), default is dry run."
    Write-Output "   -createmasterapp : If this is set, create the master app(s), otherwise it will not"

    Write-Output "     $COMMAND_NAME metadata_field_name [-force] [-createmasterapp]"
    Write-Output " "
    Write-Output "   It expects a user with the UI access, it doesn't work with API only user"
    Write-Output " "
    exit
}
elseif ( $CONTRAST_AUTH_TOKEN -eq $null -or $CONTRAST_API_KEY -eq $null -or $CONTRAST_ORG_ID -eq $null ) {
    Write-Output "You must have forgot to set the following environment variables or update the script with default values"
    Write-Output "   - `$ENV:CONTRAST_AUTH_TOKEN=`"Contrast authorization key`""
    Write-Output "   - `$ENV:CONTRAST_API_KEY=`"Contrast API Key`""
    Write-Output "   - `$ENV:CONTRAST_ORG_ID=`"Contrast Organization ID`""
    Write-Output "You can create environment variables using the following format:"
    Write-Output "`$ENV:<variable-name>=<variable-value>"
    Write-Output "For Example:"
    Write-Output "`$ENV:CONTRAST_ORG_ID=WWWW-XXXX-YYYY-ZZZZ"
    exit
}
else {
    $METADATA_FIELD_NAME = $args[0]
}
$CURRENT_TIME = Get-Current-Time
$LOG_FILE = "$LOG_DIR/$COMMAND_NAME$CURRENT_TIME.log"

Add-Log "$DRY_RUN Running $COMMAND_NAME $ARGUMENTS" $LOG_FILE "Create" 

Add-Log "$DRY_RUN Fetching application list from Contrast Team Server..." $LOG_FILE

$APP_LIST = Get-App-List-For-Org $CONTRAST_API_URL $CONTRAST_ORG_ID $CONTRAST_AUTH_TOKEN $CONTRAST_API_KEY 0 25

$UNMERGED_APPS = Get-Apps-Filtered-On-Merged-Status $APP_LIST $false

$MERGED_APPS = Get-Apps-Filtered-On-Merged-Status $APP_LIST $true

$APP_NAME_APP_ID_MAP = Get-App-Name-APP_ID-MAP $APP_LIST

Add-Log "$DRY_RUN Fetching application metadata from Contrast Team Server and building Parent-Child map using $METADATA_FIELD_NAME..." $LOG_FILE

$PARENT_CHILD_APP_MAP = Get-Metadata-App-Map $CONTRAST_API_URL $CONTRAST_ORG_ID $CONTRAST_AUTH_TOKEN $CONTRAST_API_KEY $UNMERGED_APPS $METADATA_FIELD_NAME

Add-Log "$DRY_RUN Writing application parent-child map to file $REPORT_DIR\APPS_$CURRENT_TIME.json..." $LOG_FILE
$PARENT_CHILD_APP_MAP | ConvertTo-Json -Depth 2 | Out-File "$REPORT_DIR\APPS_$CURRENT_TIME.json"

#Add-log "$DRY_RUN Filtering parent apps those are not in Contrast..." $LOG_FILE
#$PARENT_APPS_NOT_CONTRAST = Get-Parent-Apps-Not-In-Contrast $PARENT_CHILD_APP_MAP $APP_NAME_APP_ID_MAP

Add-Log "$DRY_RUN Writing parent apps to be created in $REPORT_DIR\APPS_TO_BE_CREATED_$CURRENT_TIME.json" $LOG_FILE
$PARENT_APPS_NOT_CONTRAST | ConvertTo-Json -Depth 2 | Out-File "$REPORT_DIR\APPS_TO_BE_CREATED_$CURRENT_TIME.json"

Add-log "$DRY_RUN Filtering parent apps those are already in Contrast..." $LOG_FILE
$PARENT_APPS_ALREADY_CONTRAST = Get-Parent-Apps-Already-In-Contrast $PARENT_CHILD_APP_MAP $APP_NAME_APP_ID_MAP

Add-Log "$DRY_RUN Fetching application access groups from Contrast Team Server..." $LOG_FILE
$GROUPS = Get-Groups-For-Org $CONTRAST_API_URL $CONTRAST_ORG_ID $CONTRAST_AUTH_TOKEN $CONTRAST_API_KEY 0 25

Add-Log "$DRY_RUN Building application group map..." $LOG_FILE
$APP_NAME_GROUP_MAP = Get-App-Group-Map $GROUPS

Add-Log "$DRY_RUN Writing group map to $REPORT_DIR\GROUPS_$CURRENT_TIME.json..." $LOG_FILE
$APP_NAME_GROUP_MAP | ConvertTo-Json -Depth 2 | Out-File "$REPORT_DIR\GROUPS_$CURRENT_TIME.json"
if ($createmasterapp) {
    Add-Log "$DRY_RUN Creating parent applications..." $LOG_FILE
    Add-Parent-Apps-To-Contrast $CONTRAST_API_URL $CONTRAST_ORG_ID $CONTRAST_AUTH_TOKEN $CONTRAST_API_KEY  $PARENT_APPS_NOT_CONTRAST $APP_NAME_GROUP_MAP $APP_NAME_LANGUAGE_MAP $APP_NAME_APP_ID_MAP
}else{
    Add-Log "$DRY_RUN Skipping creation of parent applications as createmasterapp is set to false..." $LOG_FILE
}

Add-Log "$DRY_RUN Adding child apps to existing parent application..." $LOG_FILE
Add-Child-Apps-To-Parent $CONTRAST_API_URL $CONTRAST_ORG_ID $CONTRAST_AUTH_TOKEN $CONTRAST_API_KEY  $PARENT_APPS_ALREADY_CONTRAST $MERGED_APPS $UNMERGED_APPS $APP_NAME_APP_ID_MAP

Add-Log "$DRY_RUN Application merge script executed successfully..." $LOG_FILE