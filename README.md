# Mewnomics - Twitch Integration for Mewgenics

**Mewnomics** is a mod for [Mewgenics](https://store.steampowered.com/app/2584040/Mewgenics/) that names all cats after your Twitch  community members!

## Installation

### Quick Start (Pre-built Release)

1. **Download** the latest release from [Releases](https://github.com/sublimnl/mewnomics/releases)
2. **Extract** `Mewnomics.exe` and `hook.dll` to your Mewgenics installation directory:
   ```
   C:\Program Files (x86)\Steam\steamapps\common\Mewgenics\
   ```
3. **Run** `Mewnomics.exe` from the Mewgenics directory
4. **Authenticate** with your Twitch account
5. **Select** which name pools you want to use
6. **Launch** and enjoy!

## Building from Source

### Requirements

- LLVM/Clang (tested with LLVM 17+)
- Git (for downloading MinHook dependency)
- Windows SDK (for resource compiler)
- **Optional**: Make (for Makefile builds)

### Installing Prerequisites (Windows)

**Quick Install with WinGet:**
```powershell
# Install LLVM/Clang
winget install LLVM.LLVM

# Install Git
winget install Git.Git

# Install Make
winget install GnuWin32.Make

# Add to PATH (restart terminal after installing)
$env:PATH += ";C:\Program Files\LLVM\bin;C:\Program Files (x86)\GnuWin32\bin"
```

**Manual Downloads:**
- LLVM: https://github.com/llvm/llvm-project/releases
- Git: https://git-scm.com/download/win
- Make: https://gnuwin32.sourceforge.net/packages/make.htm

### Build Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/sublimnl/mewnomics.git
   cd mewnomics
   ```

2. Build with make:
   ```cmd
   make
   ```

3. Copy files to your Mewgenics installation directory:
   ```cmd
   copy build\hook.dll "C:\Program Files (x86)\Steam\steamapps\common\Mewgenics\hook.dll"
   copy build\Mewnomics.exe "C:\Program Files (x86)\Steam\steamapps\common\Mewgenics\Mewnomics.exe"
   ```

**Optional - Clean build artifacts:**
```cmd
make clean       # Remove build objects
make distclean   # Remove everything including MinHook
```

#### Build Output

The Makefile will:
- Download and compile MinHook
- Compile the hook DLL (`build/hook.dll`)
- Compile the GUI launcher (`build/Mewnomics.exe`)

## How It Works

### Name Prioritization

Names are scored based on the user's Twitch status (additive):

| Category        | Score | Description                    |
|-----------------|-------|--------------------------------|
| Current Viewers | +100  | Active viewers in chat         |
| Moderators      | +75   | Channel moderators             |
| VIPs            | +75   | Channel VIPs                   |
| Subscribers     | +50   | Active subscribers             |
| Bit Givers      | +25   | Users who've given bits        |
| Followers       | +10   | Channel followers              |

Scores are **additive**, so a subscriber who is also a current viewer gets 150 points!

### Selection Algorithm

1. **Priority Tiers** - Picks from highest-scoring names first
2. **Recency Tracking** - Tracks last 50 names used to avoid immediate repeats
3. **Graceful Fallback** - If high-priority pool exhausted, moves to next tier

## Configuration

### Name Pools

You can select which Twitch groups to include:

- ✅ **Current Viewers** - Active viewers
- ✅ **Subscribers** - Current subs
- ✅ **Followers** - All followers
- ✅ **Moderators** - Channel mods
- ✅ **VIPs** - Channel VIPs
- ✅ **Bit Givers** - Users who've given bits

Settings are saved automatically and persist between sessions.

## Troubleshooting

### Authentication Issues
- **Solution**: Delete `%TEMP%/mewgenics_twitch_tokens.dat` and re-authenticate
- Make sure port 7877 is not blocked by firewall

### Names not appearing
- Check `hook_log.txt` for errors
- Verify shared memory connection succeeded
- Ensure at least 20 unique names are available

## Development

### Project Structure

**GitHub Repository (mewnomics/):**
```
mewnomics/                   # Project root
├── Makefile                 # Build script
├── README.md                # This file
├── LICENSE                  # MIT License
├── CONTRIBUTING.md          # Contribution guide
├── .gitignore              # Git exclusions
├── launcher_gui.cpp        # GUI launcher source
├── hook.cpp                # Hook DLL source
├── launcher.rc             # Resource file
├── launcher.res            # Compiled resource
├── mewgenics_icon.ico      # Launcher icon
└── build/                  # Build artifacts (gitignored)
    ├── Mewnomics.exe       # Compiled launcher
    ├── hook.dll            # Compiled hook
    └── minhook/            # MinHook dependency (auto-downloaded)
```

**Deployed to Game Directory:**
```
Mewgenics/                   # Steam game installation
├── Mewgenics.exe           # Original game
├── Mewnomics.exe           # Mod launcher
├── hook.dll                # Hook DLL
└── hook_log.txt            # Debug log (generated)
```

### Adding New Features

1. **Modify source files** in project root
2. **Rebuild** with `make`
3. **Copy files** to game directory
4. **Test** by running Mewnomics.exe from game directory
5. **Check logs** in `hook_log.txt` for debugging

### Creating a Release

Releases are fully automated via GitHub Actions:

1. **Create and push a git tag**:
   ```bash
   git tag v1.0.1           # Use semantic versioning
   git push origin v1.0.1
   ```

2. **GitHub Actions automatically**:
   - Extracts version from tag
   - Patches version in source files
   - Builds Mewnomics.exe and hook.dll
   - Creates a GitHub release with binaries
   - Users get notified of updates in the launcher!

No manual version bumping needed - just tag and push!

### Update Checker

The launcher automatically checks for updates on startup:
- Compares current version with latest GitHub release
- Shows clickable notification if update available
- Opens GitHub releases page when clicked
- No manual checking needed!

## Credits

- **Created by**: [sublimnl](https://twitch.tv/sublimnl)
- **Game**: [Mewgenics](https://store.steampowered.com/app/2584040/Mewgenics/) by Edmund McMillen & Tyler Glaiel
- **Hooking Library**: [MinHook](https://github.com/TsudaKageyu/minhook) by Tsuda Kageyu

## License

This project is provided as-is for educational and entertainment purposes. Mewgenics is owned by Edmund McMillen and Tyler Glaiel. This mod is not officially endorsed by the game developers.

## Support

- **Issues**: [GitHub Issues](https://github.com/sublimnl/mewnomics/issues)
- **Discord**: [Twitching of Isaac Discord](https://discord.com/invite/5R9CSxzcep)

---

**Made with ❤️ in some dark basement**
