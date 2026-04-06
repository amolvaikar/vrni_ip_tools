# 🚀 Bash LLM Auto-Troubleshooter

A specialized Bash hook that intercepts failed shell commands and automatically consults an LLM (Local or Cloud) to provide instant fixes directly in your terminal.

## 🛠 How it Works
This tool utilizes the Bash `DEBUG` trap and `extdebug` option:
1.  **Intercepts**: Every command you type is intercepted before execution.
2.  **Execution**: The script runs the command manually using `eval`, capturing `stdout` and `stderr` to temporary files while still piping them to your screen.
3.  **Detection**: If the command returns a non-zero exit code, the script bundles the command, the exit status, and the error logs into a prompt.
4.  **Consultation**: The prompt is sent to your configured LLM (Ollama, OpenAI, Gemini, or Anthropic).
5.  **Solution**: The LLM's explanation and fix are printed in green text immediately below the error.

## 📋 Prerequisites
* **Bash**: Version 4.0 or higher.
* **curl**: For API communication.
* **jq**: Required for safe JSON processing and response parsing.
* **Ollama (Optional)**: If you want to run everything locally and offline.

---

## ⚙️ Installation & Setup

### 1. Configure your API Keys
The script looks for a configuration file at `~/.llm_config`. Create it and restrict permissions:

```bash
touch ~/.llm_config
chmod 600 ~/.llm_config
```

Open ~/.llm_config and add your preferred provider:

Bash
### Example for OpenAI
```
export LLM_PROVIDER="openai"
export LLM_MODEL="gpt-4o"
export LLM_API_KEY="sk-..."
```
### OR Example for Local Ollama (Default)
```
export LLM_PROVIDER="ollama"
export LLM_MODEL="llama3"
```

### 2. Deploy to Bash
Add the contents of the script (provided in the bashrc section) to the end of your ~/.bashrc file. Then, reload your shell:

Bash
```
source ~/.bashrc
```

# 🌟 Examples
Scenario A: Typos or Missing Directories
User Input:

Bash
```
ls /homm/user/documents

ls: cannot access '/homm/user/documents': No such file or directory
[🤖 LLM is analyzing the error...]
You misspelled '/home'. Try: ls /home/user/documents
```

Scenario B: Permission Denied
User Input:

Bash
```
cat /etc/shadow

cat: /etc/shadow: Permission denied
[🤖 LLM is analyzing the error...]
The file requires root privileges. Run: sudo cat /etc/shadow
```

# ⚠️ Known Limitations
Interactive Tools: Commands like vim, nano, or ssh are bypassed to avoid breaking terminal TUI interfaces.

Sensitive Data: Be cautious using cloud providers (OpenAI/Gemini) if you frequently work with environment variables or files containing secrets, as the error context is sent to the API. Use Ollama for a 100% private, local experience.

Developer Note: This script uses eval. While it is scoped to your manual input, always ensure you aren't pasting untrusted multi-line snippets from the web while this hook is active!