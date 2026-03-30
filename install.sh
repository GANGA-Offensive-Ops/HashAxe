#!/usr/bin/env bash
# HashAxe Autonomous Installer
# Run via: curl -sSf https://raw.githubusercontent.com/GANGA-Offensive-Ops/Hashaxe/main/install.sh | bash

set -e

# ==========================================
# UI Colors
# ==========================================
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${BLUE}${BOLD}>>> Initialising HashAxe Autonomous Installer...${NC}"

# ==========================================
# Paths & Variables
# ==========================================
INSTALL_DIR="$HOME/.hashaxe"
BIN_DIR="$HOME/.local/bin"

mkdir -p "$BIN_DIR"

# ==========================================
# 1. System Dependencies
# ==========================================
echo -e "\n${BLUE}[1/5] Checking System Dependencies...${NC}"
if command -v apt &> /dev/null; then
    echo -e "Debian/Ubuntu/Kali detected. Installing dependencies (this may ask for your password)..."
    sudo apt-get update -y
    sudo apt-get install -y git libreoffice unrar python3 python3-pip python3-venv build-essential libssl-dev pkg-config
elif command -v pacman &> /dev/null; then
    echo -e "Arch Linux detected. Installing dependencies..."
    sudo pacman -Sy --noconfirm git libreoffice unrar python python-pip base-devel openssl
else
    echo -e "${RED}Unsupported package manager. Please ensure Python 3, Git, and build tools are installed manually.${NC}"
fi

# ==========================================
# 2. Rust Toolchain
# ==========================================
echo -e "\n${BLUE}[2/5] Checking High-Performance Rust Toolchain...${NC}"
if ! command -v cargo &> /dev/null; then
    echo -e "Rust not found. Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo -e "${GREEN}Rust is already installed: $(rustc --version)${NC}"
fi

# ==========================================
# 3. Clone / Update Repository
# ==========================================
echo -e "\n${BLUE}[3/5] Cloning HashAxe Core...${NC}"
if [ ! -d "$INSTALL_DIR" ]; then
    git clone https://github.com/GANGA-Offensive-Ops/HashAxe.git "$INSTALL_DIR"
else
    echo -e "Directory $INSTALL_DIR already exists. Pulling latest updates..."
    cd "$INSTALL_DIR" && git pull origin main
fi

cd "$INSTALL_DIR"

# ==========================================
# 4. Virtual Environment & Dependencies
# ==========================================
echo -e "\n${BLUE}[4/5] Constructing Python Virtual Environment...${NC}"
python3 -m venv venv
source venv/bin/activate

echo -e "Installing Core Dependencies..."
pip install -U pip
pip install -r requirements.txt

echo -e "Building High-Speed Rust Backends (This may take a minute)..."
if [ -d "hashaxe/native" ]; then
    cd hashaxe/native
    maturin develop --release
    cd ../../
else
    echo -e "${RED}Warning: hashaxe/native missing. Skipped Rust compilation.${NC}"
fi

# ==========================================
# 5. Global Command Wrapper
# ==========================================
echo -e "\n${BLUE}[5/5] Creating Global 'hashaxe' Command...${NC}"
WRAPPER_PATH="$BIN_DIR/hashaxe"

cat << 'EOF' > "$WRAPPER_PATH"
#!/usr/bin/env bash
# HashAxe execution wrapper
INSTALL_DIR="$HOME/.hashaxe"
source "$INSTALL_DIR/venv/bin/activate"
export PYTHONPATH="$INSTALL_DIR:$PYTHONPATH"
exec python3 -m hashaxe "$@"
EOF

chmod +x "$WRAPPER_PATH"
echo -e "${GREEN}Created binary symlink securely at --> $WRAPPER_PATH${NC}"

# ==========================================
# Final Setup & PATH Check
# ==========================================
echo -e "\n${GREEN}${BOLD}======================================================${NC}"
echo -e "${GREEN}${BOLD}  🎉 Hashaxe V1.0 INSTALLED SUCCESSFULLY! 🎉  ${NC}"
echo -e "${GREEN}${BOLD}======================================================${NC}"

# Check if ~/.local/bin is in PATH
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo -e "\n${RED}${BOLD}⚠️  WARNING: $BIN_DIR is NOT in your PATH!${NC}"
    echo -e "You must run this command once to fix it:"
    echo -e "    ${BOLD}echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc${NC}"
    echo -e "    (If you use ZSH, change .bashrc to .zshrc)\n"
else
    echo -e "\n${GREEN}Your PATH is correctly configured.${NC}"
fi

echo -e "You can now run ${BOLD}'hashaxe'${NC} globally from any directory!"
echo -e "Example usages:"
echo -e "  $ ${BLUE}hashaxe --help${NC}"
echo -e "  $ ${BLUE}hashaxe -k target.txt -w wordlist.txt --auto-pwn${NC}"
echo -e "\nWelcome to the Shadows. Happy Hacking!"
