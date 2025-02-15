#!/bin/bash
 
# SonarQube Configurations
SONARQUBE_URL="<url_sonar>"
ADMIN_USERNAME="username"
ADMIN_PASSWORD="password"
AUTH_TOKEN=$(echo -n "$ADMIN_USERNAME:$ADMIN_PASSWORD" | base64)
 
# List of relevant permissions (mapped to API values)
PERMISSIONS=("user" "codeviewer" "issueadmin")
 
# Display names for permissions
PERMISSION_DISPLAY=("Browse" "See Source Code" "Administer Issues")
 
# =============================================
# PREMIUM COLOR PALETTE & EFFECTS
# =============================================
BLACK=$(tput setaf 0)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
MAGENTA=$(tput setaf 5)
CYAN=$(tput setaf 6)
WHITE=$(tput setaf 7)
BOLD=$(tput bold)
RESET=$(tput sgr0)
BG_BLACK=$(tput setab 0)
BG_RED=$(tput setab 1)
BG_GREEN=$(tput setab 2)
BG_YELLOW=$(tput setab 3)
BG_BLUE=$(tput setab 4)
BG_MAGENTA=$(tput setab 5)
BG_CYAN=$(tput setab 6)
BG_WHITE=$(tput setab 7)

# Premium Neon Colors
NEON_RED="\e[38;5;196m"
NEON_GREEN="\e[38;5;46m"
NEON_BLUE="\e[38;5;21m"
NEON_PINK="\e[38;5;201m"
NEON_YELLOW="\e[38;5;226m"
NEON_CYAN="\e[38;5;51m"
NEON_PURPLE="\e[38;5;129m"

# Premium Background Effects
BG_COSMIC="\e[48;5;17m"
BG_STARLIGHT="\e[48;5;237m"

# ==============================================
# PREMIUM HEADER
# ==============================================
show_premium_header() {
    clear
    echo -e "\n${NEON_CYAN}${BOLD}"
    echo "    ██████╗ ██████╗ ███████╗███╗   ███╗██╗██╗   ██╗███╗   ███╗"
    echo "    ██╔══██╗██╔══██╗██╔════╝████╗ ████║██║██║   ██║████╗ ████║"
    echo "    ██████╔╝██████╔╝█████╗  ██╔████╔██║██║██║   ██║██╔████╔██║"
    echo "    ██╔═══╝ ██╔══██╗██╔══╝  ██║╚██╔╝██║██║██║   ██║██║╚██╔╝██║"
    echo "    ██║     ██║  ██║███████╗██║ ╚═╝ ██║██║╚██████╔╝██║ ╚═╝ ██║"
    echo "    ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝ ╚═════╝ ╚═╝     ╚═╝"
    echo -e "${RESET}"
    echo -e "${NEON_YELLOW}${BOLD}                SONARQUBE MEMBER MANAGER${RESET}"
    echo -e "${NEON_GREEN}${BOLD}                  PREMIUM EDITION v3.0${RESET}"
    echo -e "\n${NEON_CYAN}╔════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${NEON_CYAN}║${RESET}${NEON_PURPLE}              Welcome to Premium Experience              ${NEON_CYAN}║${RESET}"
    echo -e "${NEON_CYAN}╚════════════════════════════════════════════════════════════╝${RESET}\n"
}

# ==============================================
# PREMIUM FOOTER
# ==============================================
show_premium_footer() {
    echo -e "\n${BG_COSMIC}${NEON_PURPLE}${BOLD}"
    echo "    ╔══════════════════════════════════════════════════════════════╗"
    echo "    ║              © 2025 FSoft Technology Corporation             ║"
    echo "    ║            All Rights Reserved. Version Ultra 3.0            ║"
    echo "    ╚══════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

# ==============================================
# PREMIUM STATUS BAR
# ==============================================
show_status_bar() {
    local percent=$1
    local width=50
    local completed=$((width * percent / 100))
    
    echo -ne "${NEON_GREEN}["
    for ((i=0; i<completed; i++)); do
        echo -ne "█"
    done
    for ((i=completed; i<width; i++)); do
        echo -ne "▒"
    done
    echo -ne "] ${percent}%${RESET}\r"
}

# ==============================================
# PREMIUM HELP SECTION
# ==============================================
show_premium_help() {
    echo -e "\n${BG_STARLIGHT}${NEON_YELLOW}${BOLD} 💡 QUICK HELP 💡 ${RESET}\n"
    echo -e "${NEON_CYAN}╭───────────────────────────────────────────────────╮${RESET}"
    echo -e "${NEON_CYAN}│${RESET} ${NEON_PINK}•${RESET} Use number keys to navigate menu              ${NEON_CYAN}│${RESET}"
    echo -e "${NEON_CYAN}│${RESET} ${NEON_PINK}•${RESET} Enter usernames separated by commas          ${NEON_CYAN}│${RESET}"
    echo -e "${NEON_CYAN}│${RESET} ${NEON_PINK}•${RESET} Press Ctrl+C to exit anytime                 ${NEON_CYAN}│${RESET}"
    echo -e "${NEON_CYAN}╰───────────────────────────────────────────────────╯${RESET}"
}

# Function to print colored messages
print_info() {
    local message=$1
    echo -e "\n${NEON_CYAN}╭──────────────── ${NEON_YELLOW}ℹ️  INFO${NEON_CYAN} ─────────────────╮${RESET}"
    echo -e "${NEON_CYAN}│${RESET} ${NEON_BLUE}$message${RESET}${NEON_CYAN} │${RESET}"
    echo -e "${NEON_CYAN}╰───────────────────────────────────────────────╯${RESET}\n"
}

print_success() {
    local message=$1
    echo -e "\n${NEON_GREEN}╭────────────── ${NEON_YELLOW}✨ SUCCESS${NEON_GREEN} ───────────────╮${RESET}"
    echo -e "${NEON_GREEN}│${RESET} ${NEON_GREEN}$message${RESET}${NEON_GREEN} │${RESET}"
    echo -e "${NEON_GREEN}╰───────────────────────────────────────────────╯${RESET}\n"
}

print_error() {
    local message=$1
    echo -e "\n${NEON_RED}╭─────────────── ${NEON_YELLOW}❌ ERROR${NEON_RED} ────────────────╮${RESET}"
    echo -e "${NEON_RED}│${RESET} ${NEON_RED}$message${RESET}${NEON_RED} │${RESET}"
    echo -e "${NEON_RED}╰───────────────────────────────────────────────╯${RESET}\n"
}

print_warning() {
    local message=$1
    echo -e "\n${NEON_YELLOW}╭────────────── ${NEON_RED}⚠️  WARNING${NEON_YELLOW} ───────────────╮${RESET}"
    echo -e "${NEON_YELLOW}│${RESET} ${NEON_YELLOW}$message${RESET}${NEON_YELLOW} │${RESET}"
    echo -e "${NEON_YELLOW}╰───────────────────────────────────────────────╯${RESET}\n"
}

# Function to get existing permissions for a user
get_existing_permissions() {
    local projectKey="$1"
    local username="$2"
    local response=$(curl -s -w "%{http_code}" -u "$ADMIN_USERNAME:$ADMIN_PASSWORD" \
        "$SONARQUBE_URL/api/permissions/users?projectKey=$projectKey&q=$username")
    
    local http_code=${response: -3}
    local content=${response%???}
    
    if [ $http_code -eq 200 ]; then
        echo "$content" | jq -r '.users[].permissions[]' | sort | uniq
        return 0
    else
        print_error "Failed to get existing permissions. HTTP code: $http_code"
        echo "$content" | jq -r '.errors[].msg' 2>/dev/null || echo "Unknown error"
        return 1
    fi
}

# Function to map permission code to display name
map_permission_name() {
    local permission="$1"
    case "$permission" in
        admin) echo "Administer" ;;
        codeviewer) echo "Browse" ;;
        issueadmin) echo "Administer Issues" ;;
        scan) echo "Execute Analysis" ;;
        user) echo "User" ;;
        *) echo "$permission" ;;
    esac
}

# Function to print existing permissions in UI format
print_existing_permissions() {
    local username=$1
    local permissions=$2

    echo -e "\n${NEON_CYAN}╔════════════════════ ${NEON_BLUE}👤 USER PERMISSIONS${NEON_CYAN} ═══════════════════╗${RESET}"
    echo -e "${NEON_CYAN}║                                                              ║${RESET}"
    echo -e "${NEON_CYAN}║${RESET}  ${NEON_BLUE}Username:${RESET} ${NEON_CYAN}$username${RESET}                                          ${NEON_CYAN}║${RESET}"
    echo -e "${NEON_CYAN}║                                                              ║${RESET}"
    
    if [ -z "$permissions" ]; then
        echo -e "${NEON_CYAN}║${RESET}  ${NEON_RED}✖ No permissions assigned${RESET}                              ${NEON_CYAN}║${RESET}"
    else
        echo -e "${NEON_CYAN}║${RESET}  ${NEON_BLUE}Current Permissions:${RESET}                                    ${NEON_CYAN}║${RESET}"
        echo -e "${NEON_CYAN}║${RESET}  ${NEON_CYAN}┌──────────────────────────────────────────────────┐${RESET}     ${NEON_CYAN}║${RESET}"
        while IFS= read -r perm; do
            local display_name=$(map_permission_name "$perm")
            echo -e "${NEON_CYAN}║${RESET}  ${NEON_CYAN}│${RESET}  ${NEON_GREEN}✓${RESET} ${NEON_CYAN}${display_name}${RESET}                                      ${NEON_CYAN}│${RESET}     ${NEON_CYAN}║${RESET}"
        done <<< "$permissions"
        echo -e "${NEON_CYAN}║${RESET}  ${NEON_CYAN}└──────────────────────────────────────────────────┘${RESET}     ${NEON_CYAN}║${RESET}"
    fi
    
    echo -e "${NEON_CYAN}║                                                              ║${RESET}"
    echo -e "${NEON_CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}\n"
}

# Function to map permission code to display name
map_permission_name() {
    local perm=$1
    case $perm in
        "user")
            echo "🔍 Browse"
            ;;
        "codeviewer")
            echo "📝 See Source Code"
            ;;
        "issueadmin")
            echo "⚡ Administer Issues"
            ;;
        *)
            echo "$perm"
            ;;
    esac
}

# Function to add a user to a project
add_user_to_project() {
    local projectKey="$1"
    local username="$2"
    local permission="$3"
    
    # Get existing permissions
    existing_permissions=$(get_existing_permissions "$projectKey" "$username")
    
    # Check if permission already exists
    if echo "$existing_permissions" | grep -q "^${permission}$"; then
        print_warning "User '$username' đã có các quyền sau:"
        print_existing_permissions "$username" "$existing_permissions"
        print_warning "Bỏ qua quyền '$permission'"
        return 0
    fi
    
    # Proceed to add permission
    response=$(curl -s -w "%{http_code}" -o /dev/null -u "$ADMIN_USERNAME:$ADMIN_PASSWORD" \
        -X POST "$SONARQUBE_URL/api/permissions/add_user" \
        -d "projectKey=$projectKey&login=$username&permission=$permission")
    
    local http_code=$response
    
    if [ $http_code -eq 204 ]; then
        print_success "Đã thêm quyền '$permission' cho user '$username'"
    elif [ $http_code -eq 400 ]; then
        print_error "Invalid permission or user already has this permission"
    else
        print_error "Failed to add permission. HTTP code: $http_code"
    fi
}

# Function to remove a user from a project
remove_user_from_project() {
    local projectKey="$1"
    local username="$2"
    local permission="$3"
    
    # Get existing permissions
    existing_permissions=$(get_existing_permissions "$projectKey" "$username")
    
    # Check if permission exists
    if ! echo "$existing_permissions" | grep -q "^${permission}$"; then
        print_warning "User '$username' không có quyền '$permission'. Bỏ qua."
        return 0
    fi
    
    # Proceed to remove permission
    response=$(curl -s -w "%{http_code}" -o /dev/null -u "$ADMIN_USERNAME:$ADMIN_PASSWORD" \
        -X POST "$SONARQUBE_URL/api/permissions/remove_user" \
        -d "projectKey=$projectKey&login=$username&permission=$permission")
    
    local http_code=$response
    
    if [ $http_code -eq 204 ]; then
        print_success "Đã xóa quyền '$permission' của user '$username'"
    elif [ $http_code -eq 400 ]; then
        print_error "Invalid permission or user doesn't have this permission"
    else
        print_error "Failed to remove permission. HTTP code: $http_code"
    fi
}

# Function to validate and format project key
validate_project_key() {
    local input_key="$1"
    
    # Check if the key starts with FI.DMO.OnePlatform2025.
    if [[ ! "$input_key" =~ ^FI\.DMO\.OnePlatform2025\. ]]; then
        # If it doesn't have the prefix, add it
        if [[ ! "$input_key" =~ ^FI\.DMO\.OnePlatform2025\..+ ]]; then
            input_key="FI.DMO.OnePlatform2025.$input_key"
        fi
    fi
    
    # Validate the final format
    if [[ ! "$input_key" =~ ^FI\.DMO\.OnePlatform2025\..+ ]]; then
        echo ""
        return 1
    fi
    
    echo "$input_key"
    return 0
}

# Function to check if project exists on SonarQube
check_project_exists() {
    local projectKey="$1"
    local response=$(curl -s -w "%{http_code}" -u "$ADMIN_USERNAME:$ADMIN_PASSWORD" "$SONARQUBE_URL/api/components/show?component=$projectKey")
    
    local http_code=${response: -3}
    local content=${response%???}
    
    if [ $http_code -eq 200 ]; then
        echo "Project exists"
        return 0
    elif [ $http_code -eq 404 ]; then
        print_error "Project '$projectKey' does not exist on SonarQube"
        return 1
    else
        print_error "Failed to check project existence. HTTP code: $http_code"
        echo "$content" | jq -r '.errors[].msg' 2>/dev/null || echo "Unknown error"
        return 1
    fi
}

# Function to check if user exists
check_user_exists() {
    local username="$1"
    local response=$(curl -s -w "%{http_code}" -u "$ADMIN_USERNAME:$ADMIN_PASSWORD" "$SONARQUBE_URL/api/users/search?q=$username")
    
    local http_code=${response: -3}
    local content=${response%???}
    
    if [ $http_code -eq 200 ]; then
        local exists=$(echo "$content" | jq -e ".users[] | select(.login == \"$username\")")
        if [ -n "$exists" ]; then
            return 0
        else
            print_warning "User '$username' does not exist in SonarQube"
            return 1
        fi
    else
        print_error "Failed to check user existence. HTTP code: $http_code"
        return 1
    fi
}

# Function to list projects
list_projects() {
    local response=$(curl -s -u "$ADMIN_USERNAME:$ADMIN_PASSWORD" "$SONARQUBE_URL/api/components/search?qualifiers=TRK")
    echo "$response" | jq -r '.components[] | "\(.key) - \(.name)"' 2>/dev/null || echo "No projects found or error occurred"
}

# Function to add members with all permissions to all projects
add_members_all_projects() {
    local usernames=$1
    
    # Get list of all projects
    print_info "Fetching projects from SonarQube..."
    local projects_response=$(curl -s -u "$ADMIN_USERNAME:$ADMIN_PASSWORD" "$SONARQUBE_URL/api/components/search?qualifiers=TRK")
    
    # Extract project keys using jq
    local project_keys=($(echo "$projects_response" | jq -r '.components[].key' 2>/dev/null))
    
    if [ ${#project_keys[@]} -eq 0 ]; then
        print_error "No projects found in SonarQube"
        return 1
    fi
    
    # All available permissions in SonarQube
    local all_permissions=("admin" "codeviewer" "issueadmin" "securityhotspotadmin" "scan" "user")
    
    # Process each username
    IFS=',' read -ra username_array <<< "$usernames"
    for username in "${username_array[@]}"; do
        username=$(echo "$username" | xargs)  # Trim whitespace
        
        # Validate user exists
        if ! check_user_exists "$username"; then
            print_error "User $username does not exist in SonarQube"
            continue
        fi
        
        print_info "Adding user ${NEON_GREEN}$username${RESET} to all projects with full permissions..."
        
        # Add user to each project with all permissions
        for project_key in "${project_keys[@]}"; do
            echo -e "${CYAN}Processing project: $project_key${RESET}"
            
            for permission in "${all_permissions[@]}"; do
                curl -s -u "$ADMIN_USERNAME:$ADMIN_PASSWORD" \
                    -X POST \
                    "$SONARQUBE_URL/api/permissions/add_user" \
                    -d "login=$username" \
                    -d "permission=$permission" \
                    -d "projectKey=$project_key" > /dev/null
            done
            print_success "Added $username to $project_key with all permissions"
        done
    done
    
    print_success "Completed adding users to all projects"
}

# Function to add members with view-only permissions to all projects
add_members_view_only_all_projects() {
    local usernames=$1
    
    # Get list of all projects
    print_info "Fetching projects from SonarQube..."
    local projects_response=$(curl -s -u "$ADMIN_USERNAME:$ADMIN_PASSWORD" "$SONARQUBE_URL/api/components/search?qualifiers=TRK")
    
    # Extract project keys using jq
    local project_keys=($(echo "$projects_response" | jq -r '.components[].key' 2>/dev/null))
    
    if [ ${#project_keys[@]} -eq 0 ]; then
        print_error "No projects found in SonarQube"
        return 1
    fi
    
    # View-only permissions in SonarQube
    local view_permissions=("user" "codeviewer")
    
    # Process each username
    IFS=',' read -ra username_array <<< "$usernames"
    for username in "${username_array[@]}"; do
        username=$(echo "$username" | xargs)  # Trim whitespace
        
        # Validate user exists
        if ! check_user_exists "$username"; then
            print_error "User $username does not exist in SonarQube"
            continue
        fi
        
        print_info "Adding user ${NEON_GREEN}$username${RESET} to all projects with view-only permissions..."
        
        # Add user to each project with view permissions
        for project_key in "${project_keys[@]}"; do
            echo -e "${CYAN}Processing project: $project_key${RESET}"
            
            for permission in "${view_permissions[@]}"; do
                curl -s -u "$ADMIN_USERNAME:$ADMIN_PASSWORD" \
                    -X POST \
                    "$SONARQUBE_URL/api/permissions/add_user" \
                    -d "login=$username" \
                    -d "permission=$permission" \
                    -d "projectKey=$project_key" > /dev/null
            done
            print_success "Added $username to $project_key with view-only permissions"
        done
    done
    
    print_success "Completed adding users to all projects with view-only permissions"
}

# Function to show exit message
show_exit_message() {
    echo -e "\n${NEON_CYAN}╔════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${NEON_CYAN}║                                                              ║${RESET}"
    echo -e "${NEON_CYAN}║${RESET}     ${NEON_YELLOW}Thank you for using SonarQube Member Manager!${RESET}         ${NEON_CYAN}║${RESET}"
    echo -e "${NEON_CYAN}║${RESET}                                                              ${NEON_CYAN}║${RESET}"
    echo -e "${NEON_CYAN}║${RESET}     ${NEON_GREEN}✨ Your changes have been applied successfully ✨${RESET}        ${NEON_CYAN}║${RESET}"
    echo -e "${NEON_CYAN}║${RESET}                                                              ${NEON_CYAN}║${RESET}"
    echo -e "${NEON_CYAN}╠══════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${NEON_CYAN}║${RESET}     ${NEON_PURPLE}© 2025 FSoft Technology Corporation${RESET}                    ${NEON_CYAN}║${RESET}"
    echo -e "${NEON_CYAN}║${RESET}     ${NEON_BLUE}Version: Premium Edition v3.0${RESET}                           ${NEON_CYAN}║${RESET}"
    echo -e "${NEON_CYAN}║${RESET}                                                              ${NEON_CYAN}║${RESET}"
    echo -e "${NEON_CYAN}╚════════════════════════════════════════════════════════════╝${RESET}\n"
}

# Main execution
show_premium_header

echo -e "${NEON_CYAN}╭───────────────────────────────────────────────────────────╮${RESET}"
echo -e "${NEON_CYAN}│${RESET}                   ${NEON_YELLOW}SONARQUBE USER MANAGER${RESET}                  ${NEON_CYAN}│${RESET}"
echo -e "${NEON_CYAN}├───────────────────────────────────────────────────────────┤${RESET}"
echo -e "${NEON_CYAN}│${RESET} ${WHITE}1.${RESET} Add members to a specific project                      ${NEON_CYAN}│${RESET}"
echo -e "${NEON_CYAN}│${RESET} ${WHITE}2.${RESET} Remove members from a specific project                 ${NEON_CYAN}│${RESET}"
echo -e "${NEON_CYAN}│${RESET} ${WHITE}3.${RESET} List all projects                                     ${NEON_CYAN}│${RESET}"
echo -e "${NEON_CYAN}│${RESET} ${WHITE}4.${RESET} Add members with full permissions to all projects     ${NEON_CYAN}│${RESET}"
echo -e "${NEON_CYAN}│${RESET} ${WHITE}5.${RESET} Add members with view-only permissions to all projects${NEON_CYAN}│${RESET}"
echo -e "${NEON_CYAN}│${RESET} ${WHITE}0.${RESET} Exit                                                 ${NEON_CYAN}│${RESET}"
echo -e "${NEON_CYAN}╰───────────────────────────────────────────────────────────╯${RESET}"

read -p "$(echo -e ${NEON_YELLOW}"Enter your choice [0-5]: "${RESET})" action

if [[ "$action" == "1" ]]; then
    echo -e "\n${NEON_CYAN}╭──────────────── ${NEON_YELLOW}AVAILABLE PROJECTS${NEON_CYAN} ────────────────╮${RESET}"
    print_info "Here are all available projects in SonarQube:"
    list_projects
    
    echo -e "\n${NEON_CYAN}╭──────────────── ${NEON_YELLOW}ADD MEMBERS${NEON_CYAN} ────────────────╮${RESET}"
    print_info "Adding members to a specific project..."
    echo -e "\n${NEON_YELLOW}Enter project key (e.g. FI.DMO.OnePlatform2025.my-repo):${RESET}"
    read projectKey
    
    if [ -z "$projectKey" ]; then
        print_error "Project key is required."
    else
        projectKey=$(validate_project_key "$projectKey")
        
        if [ -z "$projectKey" ]; then
            print_error "Invalid project key format. It should be either:"
            print_error "1. Repository name (e.g., 'my-repo')"
            print_error "2. Full project key (e.g., 'FI.DMO.OnePlatform2025.my-repo')"
        else
            # Check if project exists
            if ! check_project_exists "$projectKey"; then
                print_warning "Please enter a valid project key"
            else
                print_info "Using project key: ${GREEN}$projectKey${NC}"
                
                # Permission selection with retry
                while true; do
                    echo -e "\n${NEON_CYAN}╔═════════════════ ${NEON_YELLOW}AVAILABLE PERMISSIONS${NEON_CYAN} ════════════════╗${RESET}"
                    echo -e "${NEON_CYAN}║                                                              ║${RESET}"
                    echo -e "${NEON_CYAN}║${RESET}  ${NEON_GREEN}1.${RESET} ${NEON_CYAN}🔍 Browse${RESET}                                               ${NEON_CYAN}║${RESET}"
                    echo -e "${NEON_CYAN}║${RESET}  ${NEON_GREEN}2.${RESET} ${NEON_CYAN}📝 See Source Code${RESET}                                     ${NEON_CYAN}║${RESET}"
                    echo -e "${NEON_CYAN}║${RESET}  ${NEON_GREEN}3.${RESET} ${NEON_CYAN}⚡ Administer Issues${RESET}                                   ${NEON_CYAN}║${RESET}"
                    echo -e "${NEON_CYAN}║${RESET}  ${NEON_GREEN}4.${RESET} ${NEON_CYAN}✨ All (Browse, See Source Code, Administer Issues)${RESET}    ${NEON_CYAN}║${RESET}"
                    echo -e "${NEON_CYAN}║                                                              ║${RESET}"
                    echo -e "${NEON_CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}"
                    echo -e "\n${NEON_YELLOW}Enter the permission number you want to manage (1-4):${RESET} "

                    read -p "> " permission_choice
                    
                    if [[ "$permission_choice" =~ ^[0-9]+$ ]] && ((permission_choice >= 1 && permission_choice <= 4)); then
                        break
                    else
                        print_error "Invalid permission choice. Please enter a number between 1 and 4."
                    fi
                done
                
                # Set selected permissions
                if [ "$permission_choice" -eq 4 ]; then
                    selected_permissions=("${PERMISSIONS[@]}")
                else
                    selected_permissions=("${PERMISSIONS[$((permission_choice-1))]}")
                fi
                
                echo -e "\n${NEON_CYAN}╭──────────────── ${NEON_YELLOW}ADD MEMBERS${NEON_CYAN} ────────────────╮${RESET}"
                print_info "Adding members to project '${NEON_GREEN}$projectKey${RESET}' with permissions: ${selected_permissions[*]}..."
                echo -e "\n${NEON_YELLOW}Enter usernames ${WHITE}(separated by commas, e.g. ${NEON_CYAN}vinhtt20,dunglt42,nguyenvanb${WHITE}):${RESET}"
                
                total_users=0
                while true; do
                    read -p "> " input_users
                    if [[ "$input_users" == "done" ]]; then
                        break
                    fi
                    
                    IFS=',' read -ra users <<< "$input_users"
                    for username in "${users[@]}"; do
                        username=$(echo "$username" | xargs)
                        if [ -z "$username" ]; then
                            print_error "Username cannot be empty"
                            continue
                        fi
                        
                        if ! check_user_exists "$username"; then
                            print_warning "Skipping invalid user: $username"
                            continue
                        fi
                        
                        for permission in "${selected_permissions[@]}"; do
                            add_user_to_project "$projectKey" "$username" "$permission"
                        done
                        total_users=$((total_users + 1))
                    done
                    
                    echo -e "${GREEN}Đã xử lý ${total_users} user. Nhập tiếp hoặc 'done' để kết thúc${NC}"
                done
                print_success "Đã thêm thành công ${total_users} user vào project"
            fi
        fi
    fi
elif [[ "$action" == "2" ]]; then
    echo -e "\n${NEON_CYAN}╭──────────────── ${NEON_YELLOW}AVAILABLE PROJECTS${NEON_CYAN} ────────────────╮${RESET}"
    print_info "Here are all available projects in SonarQube:"
    list_projects
    
    echo -e "\n${NEON_CYAN}╭─────────────── ${NEON_YELLOW}REMOVE MEMBERS${NEON_CYAN} ───────────────╮${RESET}"
    print_info "Removing members from a specific project..."
    echo -e "\n${NEON_YELLOW}Enter project key (e.g. FI.DMO.OnePlatform2025.my-repo):${RESET}"
    read projectKey
    
    if [ -z "$projectKey" ]; then
        print_error "Project key is required."
    else
        projectKey=$(validate_project_key "$projectKey")
        
        if [ -z "$projectKey" ]; then
            print_error "Invalid project key format. It should be either:"
            print_error "1. Repository name (e.g., 'my-repo')"
            print_error "2. Full project key (e.g., 'FI.DMO.OnePlatform2025.my-repo')"
        else
            # Check if project exists
            if ! check_project_exists "$projectKey"; then
                print_warning "Please enter a valid project key"
            else
                print_info "Using project key: ${GREEN}$projectKey${NC}"
                
                # Permission selection with retry
                while true; do
                    echo -e "\n${NEON_CYAN}╔═════════════════ ${NEON_YELLOW}AVAILABLE PERMISSIONS${NEON_CYAN} ════════════════╗${RESET}"
                    echo -e "${NEON_CYAN}║                                                              ║${RESET}"
                    echo -e "${NEON_CYAN}║${RESET}  ${NEON_GREEN}1.${RESET} ${NEON_CYAN}🔍 Browse${RESET}                                               ${NEON_CYAN}║${RESET}"
                    echo -e "${NEON_CYAN}║${RESET}  ${NEON_GREEN}2.${RESET} ${NEON_CYAN}📝 See Source Code${RESET}                                     ${NEON_CYAN}║${RESET}"
                    echo -e "${NEON_CYAN}║${RESET}  ${NEON_GREEN}3.${RESET} ${NEON_CYAN}⚡ Administer Issues${RESET}                                   ${NEON_CYAN}║${RESET}"
                    echo -e "${NEON_CYAN}║${RESET}  ${NEON_GREEN}4.${RESET} ${NEON_CYAN}✨ All (Browse, See Source Code, Administer Issues)${RESET}    ${NEON_CYAN}║${RESET}"
                    echo -e "${NEON_CYAN}║                                                              ║${RESET}"
                    echo -e "${NEON_CYAN}╚══════════════════════════════════════════════════════════════╝${RESET}"
                    echo -e "\n${NEON_YELLOW}Enter the permission number you want to manage (1-4):${RESET} "

                    read -p "> " permission_choice
                    
                    if [[ "$permission_choice" =~ ^[0-9]+$ ]] && ((permission_choice >= 1 && permission_choice <= 4)); then
                        break
                    else
                        print_error "Invalid permission choice. Please enter a number between 1 and 4."
                    fi
                done
                
                # Set selected permissions
                if [ "$permission_choice" -eq 4 ]; then
                    selected_permissions=("${PERMISSIONS[@]}")
                else
                    selected_permissions=("${PERMISSIONS[$((permission_choice-1))]}")
                fi
                
                echo -e "\n${NEON_CYAN}╭─────────────── ${NEON_YELLOW}REMOVE MEMBERS${NEON_CYAN} ───────────────╮${RESET}"
                print_info "Removing members from project '${NEON_GREEN}$projectKey${RESET}' with permissions: ${selected_permissions[*]}..."
                echo -e "\n${NEON_YELLOW}Enter usernames ${WHITE}(separated by commas, e.g. ${NEON_CYAN}vinhtt20,dunglt42,nguyenvanb${WHITE}):${RESET}"

                total_users=0
                while true; do
                    read -p "> " input_users
                    if [[ "$input_users" == "done" ]]; then
                        break
                    fi
                    
                    IFS=',' read -ra users <<< "$input_users"
                    for username in "${users[@]}"; do
                        username=$(echo "$username" | xargs)
                        if [ -z "$username" ]; then
                            print_error "Username cannot be empty"
                            continue
                        fi
                        
                        if ! check_user_exists "$username"; then
                            print_warning "Skipping invalid user: $username"
                            continue
                        fi
                        
                        for permission in "${selected_permissions[@]}"; do
                            remove_user_from_project "$projectKey" "$username" "$permission"
                        done
                        total_users=$((total_users + 1))
                    done
                    
                    echo -e "${GREEN}Đã xử lý ${total_users} user. Nhập tiếp hoặc 'done' để kết thúc${NC}"
                done
                print_success "Đã xóa thành công ${total_users} user khỏi project"
            fi
        fi
    fi
elif [[ "$action" == "3" ]]; then
    echo -e "\n${NEON_CYAN}╭──────────────── ${NEON_YELLOW}LIST ALL PROJECTS${NEON_CYAN} ───────────────╮${RESET}"
    print_info "Listing all projects..."
    list_projects
elif [[ "$action" == "4" ]]; then
    echo -e "\n${NEON_CYAN}╭──────────────── ${NEON_YELLOW}AVAILABLE PROJECTS${NEON_CYAN} ────────────────╮${RESET}"
    print_info "Here are all projects that members will be added to:"
    list_projects
    
    echo -e "\n${NEON_CYAN}╭──────────────── ${NEON_YELLOW}ADD MEMBERS TO ALL PROJECTS${NEON_CYAN} ────────────────╮${RESET}"
    echo -e "\n${NEON_YELLOW}Enter usernames ${WHITE}(separated by commas, e.g. ${NEON_CYAN}vinhtt20,dunglt42,nguyenvanb${WHITE}):${RESET}"
    read usernames
    
    if [[ -z "$usernames" ]]; then
        print_error "No usernames provided"
    else
        add_members_all_projects "$usernames"
    fi
elif [[ "$action" == "5" ]]; then
    echo -e "\n${NEON_CYAN}╭──────────────── ${NEON_YELLOW}ADD MEMBERS VIEW-ONLY${NEON_CYAN} ────────────────╮${RESET}"
    read -p "$(echo -e ${NEON_YELLOW}"Enter usernames (comma-separated): "${RESET})" usernames
    
    if [ -z "$usernames" ]; then
        print_error "No usernames provided"
    else
        add_members_view_only_all_projects "$usernames"
    fi
elif [[ "$action" == "0" ]]; then
    show_exit_message
    echo -e "\n${NEON_RED}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${NEON_RED}║                                                              ║${RESET}"
    echo -e "${NEON_RED}║${RESET}          ${NEON_YELLOW}🌟 CHƯƠNG TRÌNH KẾT THÚC THÀNH CÔNG 🌟${RESET}           ${NEON_RED}║${RESET}"
    echo -e "${NEON_RED}║${RESET}          ${NEON_CYAN}Hẹn gặp lại trong phiên làm việc tới!${RESET}             ${NEON_RED}║${RESET}"
    echo -e "${NEON_RED}║                                                              ║${RESET}"
    echo -e "${NEON_RED}╚══════════════════════════════════════════════════════════════╝${RESET}\n"
    exit 0
fi

# Function to check if user has specific permission on project
check_user_permission() {
    local username=$1
    local project_key=$2
    local permission=$3
    
    local response=$(curl -s -u "$ADMIN_USERNAME:$ADMIN_PASSWORD" \
        "$SONARQUBE_URL/api/permissions/users?projectKey=$project_key&permission=$permission" \
        | jq -r --arg user "$username" '.users[] | select(.login == $user) | .login')
    
    if [ "$response" == "$username" ]; then
        return 0  # User has permission
    else
        return 1  # User doesn't have permission
    fi
}

# Function to add members with all permissions to all projects
add_members_all_projects() {
    local usernames=$1
    
    # Get list of all projects
    print_info "Fetching projects from SonarQube..."
    local projects_response=$(curl -s -u "$ADMIN_USERNAME:$ADMIN_PASSWORD" "$SONARQUBE_URL/api/components/search?qualifiers=TRK")
    
    # Extract project keys using jq
    local project_keys=($(echo "$projects_response" | jq -r '.components[].key' 2>/dev/null))
    
    if [ ${#project_keys[@]} -eq 0 ]; then
        print_error "No projects found in SonarQube"
        return 1
    fi
    
    # All available permissions in SonarQube
    local all_permissions=("admin" "codeviewer" "issueadmin" "securityhotspotadmin" "scan" "user")
    
    # Process each username
    IFS=',' read -ra username_array <<< "$usernames"
    for username in "${username_array[@]}"; do
        username=$(echo "$username" | xargs)  # Trim whitespace
        
        # Validate user exists
        if ! check_user_exists "$username"; then
            print_error "User $username does not exist in SonarQube"
            continue
        fi
        
        print_info "Adding user ${NEON_GREEN}$username${RESET} to all projects with full permissions..."
        
        # Add user to each project with all permissions
        for project_key in "${project_keys[@]}"; do
            echo -e "${CYAN}Processing project: $project_key${RESET}"
            local permissions_added=0
            local permissions_existing=0
            
            for permission in "${all_permissions[@]}"; do
                if check_user_permission "$username" "$project_key" "$permission"; then
                    echo -e "  ${YELLOW}⚠️  Permission '$permission' already exists${RESET}"
                    ((permissions_existing++))
                    continue
                fi
                
                curl -s -u "$ADMIN_USERNAME:$ADMIN_PASSWORD" \
                    -X POST \
                    "$SONARQUBE_URL/api/permissions/add_user" \
                    -d "login=$username" \
                    -d "permission=$permission" \
                    -d "projectKey=$project_key" > /dev/null
                
                if [ $? -eq 0 ]; then
                    ((permissions_added++))
                fi
            done
            
            if [ $permissions_added -eq 0 ] && [ $permissions_existing -eq ${#all_permissions[@]} ]; then
                echo -e "  ${YELLOW}⚠️  User already has all permissions on this project${RESET}"
            else
                print_success "Added $permissions_added new permissions for $username to $project_key (${permissions_existing} permissions already existed)"
            fi
        done
    done
    
    print_success "Completed adding users to all projects"
    echo -e "${NEON_CYAN}╔════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${NEON_CYAN}║${RESET}                   ${NEON_YELLOW}Operation Summary${RESET}                    ${NEON_CYAN}║${RESET}"
    echo -e "${NEON_CYAN}╠════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${NEON_CYAN}║${RESET} ✅ Users processed: ${#username_array[@]}                              ${NEON_CYAN}║${RESET}"
    echo -e "${NEON_CYAN}║${RESET} 🎯 Projects processed: ${#project_keys[@]}                            ${NEON_CYAN}║${RESET}"
    echo -e "${NEON_CYAN}║${RESET} 🔑 Permissions per project: ${#all_permissions[@]}                    ${NEON_CYAN}║${RESET}"
    echo -e "${NEON_CYAN}╚════════════════════════════════════════════════════════════╝${RESET}"
}

# Function to add members with view-only permissions to all projects
add_members_view_only_all_projects() {
    local usernames=$1
    
    # Get list of all projects
    print_info "Fetching projects from SonarQube..."
    local projects_response=$(curl -s -u "$ADMIN_USERNAME:$ADMIN_PASSWORD" "$SONARQUBE_URL/api/components/search?qualifiers=TRK")
    
    # Extract project keys using jq
    local project_keys=($(echo "$projects_response" | jq -r '.components[].key' 2>/dev/null))
    
    if [ ${#project_keys[@]} -eq 0 ]; then
        print_error "No projects found in SonarQube"
        return 1
    fi
    
    # View-only permissions in SonarQube
    local view_permissions=("user" "codeviewer")
    
    # Process each username
    IFS=',' read -ra username_array <<< "$usernames"
    for username in "${username_array[@]}"; do
        username=$(echo "$username" | xargs)  # Trim whitespace
        
        # Validate user exists
        if ! check_user_exists "$username"; then
            print_error "User $username does not exist in SonarQube"
            continue
        fi
        
        print_info "Adding user ${NEON_GREEN}$username${RESET} to all projects with view-only permissions..."
        
        # Add user to each project with view permissions
        for project_key in "${project_keys[@]}"; do
            echo -e "${CYAN}Processing project: $project_key${RESET}"
            local permissions_added=0
            local permissions_existing=0
            
            for permission in "${view_permissions[@]}"; do
                if check_user_permission "$username" "$project_key" "$permission"; then
                    echo -e "  ${YELLOW}⚠️  Permission '$permission' already exists${RESET}"
                    ((permissions_existing++))
                    continue
                fi
                
                curl -s -u "$ADMIN_USERNAME:$ADMIN_PASSWORD" \
                    -X POST \
                    "$SONARQUBE_URL/api/permissions/add_user" \
                    -d "login=$username" \
                    -d "permission=$permission" \
                    -d "projectKey=$project_key" > /dev/null
                
                if [ $? -eq 0 ]; then
                    ((permissions_added++))
                fi
            done
            
            if [ $permissions_added -eq 0 ] && [ $permissions_existing -eq ${#view_permissions[@]} ]; then
                echo -e "  ${YELLOW}⚠️  User already has all view permissions on this project${RESET}"
            else
                print_success "Added $permissions_added new permissions for $username to $project_key (${permissions_existing} permissions already existed)"
            fi
        done
    done
    
    print_success "Completed adding users to all projects with view-only permissions"
    echo -e "${NEON_CYAN}╔════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${NEON_CYAN}║${RESET}                   ${NEON_YELLOW}Operation Summary${RESET}                    ${NEON_CYAN}║${RESET}"
    echo -e "${NEON_CYAN}╠════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${NEON_CYAN}║${RESET} ✅ Users processed: ${#username_array[@]}                              ${NEON_CYAN}║${RESET}"
    echo -e "${NEON_CYAN}║${RESET} 🎯 Projects processed: ${#project_keys[@]}                            ${NEON_CYAN}║${RESET}"
    echo -e "${NEON_CYAN}║${RESET} 🔑 View permissions added: ${#view_permissions[@]}                    ${NEON_CYAN}║${RESET}"
    echo -e "${NEON_CYAN}╚════════════════════════════════════════════════════════════╝${RESET}"
}