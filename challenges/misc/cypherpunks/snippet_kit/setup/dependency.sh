#!/bin/bash
set -e

echo "=== Détection de la distribution ==="
if [ -f /etc/debian_version ]; then
    DISTRO="debian"
elif [ -f /etc/arch-release ]; then
    DISTRO="arch"
else
    DISTRO="unknown"
fi

echo "=== Distribution détectée : $DISTRO ==="

### --- Installation pour Ubuntu/Debian ---
if [ "$DISTRO" == "debian" ]; then
    echo "=== Mise à jour du système (Ubuntu/Debian) ==="
    sudo apt update && sudo apt upgrade -y

    echo "=== Installation des dépendances ==="
    sudo apt install -y curl wget git build-essential pkg-config libssl-dev

    echo "=== Installation de Rust ==="
    if ! command -v rustc &> /dev/null; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source $HOME/.cargo/env
    fi

    echo "=== Installation de Solana CLI ==="
    sh -c "$(curl -sSfL https://release.solana.com/stable/install)"
    export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"


    solana --version
fi


### --- Installation pour Arch Linux ---
if [ "$DISTRO" = "arch" ]; then
    echo "=== Mise à jour du système (Arch Linux) ==="
    sudo pacman -Syu --noconfirm

    echo "=== Installation des dépendances ==="
    sudo pacman -S --noconfirm curl wget git base-devel pkgconf openssl

    echo "=== Installation de yay (si absent) ==="
    if ! command -v yay &> /dev/null; then
        echo "yay non trouvé, installation en cours..."
        git clone https://aur.archlinux.org/yay.git /tmp/yay
        cd /tmp/yay || exit 1
        makepkg -si --noconfirm
        cd - || exit 1
    else
        echo "yay est déjà installé."
    fi

    echo "=== Installation de Rust ==="
    if ! command -v rustc &> /dev/null; then
        sudo pacman -S --noconfirm rust
    else
        echo "Rust est déjà installé."
    fi

    echo "=== Installation de Solana CLI ==="
    yay -Syu --noconfirm solana-bin

    echo "=== Vérification de Solana ==="
    if ! command -v solana &> /dev/null; then
        echo "⚠️ Solana CLI n'a pas été ajouté au PATH, tu devras l'ajouter manuellement."
    else
        solana --version
    fi
fi

