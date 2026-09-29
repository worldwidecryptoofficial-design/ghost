# Ghost 👻

**A real, multi-provider AI assistant for Termux that generates and runs Python projects.**

## Quick installation

Copy and paste these commands into Termux:

```bash
pkg update -y && pkg upgrade -y
pkg install -y python git

git clone https://github.com/worldwidecryptoofficial-design/ghost.git
cd ghost

python -m pip install --upgrade pip
python -m pip install requests rich
chmod +x ghost ghost-generator

./ghost
```

The setup is also available in [`INSTALL.md`](INSTALL.md).

## Configure an AI provider

Ghost uses real provider APIs. Set **at least one** API key before starting it. For example:

```bash
export GROQ_API_KEY="your_groq_api_key"
./ghost
```

Other supported providers:

```bash
export OPENAI_API_KEY="your_openai_api_key"
export ANTHROPIC_API_KEY="your_anthropic_api_key"
export COHERE_API_KEY="your_cohere_api_key"
export GEMINI_API_KEY="your_gemini_api_key"
```

To keep a key available in future Termux sessions, add the relevant `export` command to `~/.bashrc` or `~/.zshrc`. Never commit API keys to this repository.

## Run the generator

```bash
cd ~/ghost
./ghost-generator
```

Describe the Python project you want, review the generated code, then choose whether to save or execute it. Generated code is not guaranteed to be safe or correct: inspect it before running it, especially when it accesses files, networks, credentials, or system commands.

## What it supports

- OpenAI, Groq, Anthropic Claude, Cohere, and Google Gemini providers
- Interactive terminal assistant named `ghost`
- Python code generation through `ghost-generator`
- Saving generated scripts
- Running authorized local commands and Python programs

Ghost does not make every request safe, legal, or technically possible. Use security tools only on systems you own or are explicitly authorized to test.

## Troubleshooting

```bash
python --version
python -m pip install --upgrade requests rich
chmod +x ghost ghost-generator
```

If `./ghost` reports that no API key is configured, set one of the environment variables above and run it again.

## Repository

https://github.com/worldwidecryptoofficial-design/ghost

## License

MIT
