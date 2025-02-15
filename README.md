# SonarQube Member Manager - Premium Edition

## 📌 Introduction
**SonarQube Member Manager** is a **Bash** script designed to automate the management of member permissions in **SonarQube**, allowing the addition and removal of members from projects with specific roles.

## ✨ Key Features
✅ **Add members to a project with specific permissions**  
✅ **Remove members from a project**  
✅ **Grant full permissions to members across all projects**  
✅ **Grant view-only permissions to members across all projects**  
✅ **List all projects on SonarQube**  
✅ **Check the current permissions of a member on a project**  
✅ **Beautiful CLI interface with neon colors & effects**  

## 🛠️ System Requirements
- **Bash Shell** (Linux/macOS or Windows with Git Bash)
- **curl**
- **jq**
- **SonarQube API Credentials** (Admin account)

## 📥 Installation
```sh
# Clone repo
git clone https://github.com/your-repo/sonarqube-member-manager.git
cd sonarqube-member-manager

# Grant execution permission
chmod +x manage_sonarqube.sh
```

## 🚀 Usage
### 1️⃣ Run the Script
```sh
./manage_sonarqube.sh
```
Once executed, the CLI interface will display options:
- **1**: Add members to a specific project
- **2**: Remove members from a specific project
- **3**: List all projects
- **4**: Add members with full permissions to all projects
- **5**: Add members with view-only permissions to all projects
- **0**: Exit

### 2️⃣ Add Members to a Project
1. Select **1** (Add members to a specific project)
2. Enter the **project key** (e.g., `FI.DMO.OnePlatform2025.my-repo`)
3. Choose permission level:
   - **1**: 🔍 Browse
   - **2**: 📝 See Source Code
   - **3**: ⚡ Administer Issues
   - **4**: ✨ All (Browse, See Source Code, Administer Issues)
4. Enter usernames (comma-separated)
5. The script processes the request and displays results

### 3️⃣ Remove Members from a Project
1. Select **2** (Remove members from a specific project)
2. Enter the **project key**
3. Choose the permission to remove
4. Enter usernames to be removed
5. The script processes the request and displays results

### 4️⃣ Add Members to All Projects
- **Full permissions**: Select **4** → enter usernames
- **View-only permissions**: Select **5** → enter usernames

## ⚠️ Notes
- **Verify project key before making changes**
- **The executing account must have admin rights on SonarQube**
- **Do not share API credentials publicly**


