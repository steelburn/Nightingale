# syntax=docker/dockerfile:1.4
###############################################################################
# Nightingale: Docker for Pentesters
# Description: Multi-stage build for comprehensive pentesting environment
# Author: Raja Nagori <raja.nagori@owasp.org>
# License: GPL-3.0
# GitHub: https://github.com/RAJANAGORI/Nightingale
#
# Defaults produce the AMD64 :stable image. ARM64:
#   docker buildx build --platform linux/arm64 \
#     --build-arg IMAGE_TAG=arm64 --build-arg ARCH=arm64 \
#     --build-arg EXTRA_APT_PACKAGES=netcat-openbsd \
#     -t nightingale:arm64 .
###############################################################################

ARG IMAGE_TAG=stable
FROM ghcr.io/rajanagori/nightingale_programming_image:${IMAGE_TAG} AS base

ARG IMAGE_TAG
ARG ARCH=amd64
ARG EXTRA_APT_PACKAGES=

LABEL org.opencontainers.image.title="Nightingale ${ARCH}" \
      org.opencontainers.image.description="Docker image for penetration testing with 100+ security tools (${ARCH})" \
      org.opencontainers.image.authors="Raja Nagori <raja.nagori@owasp.org>" \
      org.opencontainers.image.licenses="GPL-3.0 license" \
      org.opencontainers.image.url="https://github.com/RAJANAGORI/Nightingale" \
      org.opencontainers.image.source="https://github.com/RAJANAGORI/Nightingale" \
      org.opencontainers.image.documentation="https://github.com/RAJANAGORI/Nightingale/wiki" \
      org.opencontainers.image.version="2.0.0" \
      architecture="${ARCH}"

ARG DEBIAN_FRONTEND=noninteractive

RUN set -eux; \
    apt-get update -y; \
    apt-get install -y --no-install-recommends \
        bash ca-certificates build-essential cmake locate snapd tree zsh figlet unzip p7zip-full ftp ssh git curl wget file nano vim dirb nmap htop traceroute telnet net-tools iputils-ping tcpdump openvpn whois host tor john cewl hydra medusa dnsutils android-framework-res adb apktool exiftool binwalk foremost dos2unix postgresql postgresql-client postgresql-contrib pipx pv hashcat hashcat-data ${EXTRA_APT_PACKAGES}; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*; \
    command -v git >/dev/null || { echo "git not installed"; exit 1; }; \
    command -v curl >/dev/null || { echo "curl not installed"; exit 1; }; \
    command -v bash >/dev/null || { echo "bash not installed"; exit 1; }

###############################################################################
# Stage 2: Configuration and Scripts
###############################################################################
FROM base AS intermediate

ARG IMAGE_TAG

COPY --chmod=755 shells/banner.sh /tmp/banner.sh

RUN set -eux; \
    dos2unix ${HOME}/.bashrc; \
    cat /tmp/banner.sh >> ${HOME}/.bashrc; \
    echo 'main' >> ${HOME}/.bashrc; \
    mkdir -p /home/tools_web_vapt /home/tools_osint /home/tools_mobile_vapt /home/tools_network_vapt \
        /home/tools_red_teaming /home/tools_forensics /home/wordlist /home/binaries /home/.gf /home/.shells; \
    rm -f /tmp/banner.sh

ENV TOOLS_WEB_VAPT=/home/tools_web_vapt \
    BINARIES=/home/binaries \
    GREP_PATTERNS=/home/.gf \
    TOOLS_OSINT=/home/tools_osint \
    TOOLS_MOBILE_VAPT=/home/tools_mobile_vapt \
    TOOLS_NETWORK_VAPT=/home/tools_network_vapt \
    TOOLS_RED_TEAMING=/home/tools_red_teaming \
    TOOLS_FORENSICS=/home/tools_forensics \
    WORDLIST=/home/wordlist \
    METASPLOIT_CONFIG=/home/metasploit_config \
    METASPLOIT_TOOL=/home/metasploit \
    SHELLS=/home/.shells \
    GOPATH=/home/go

ENV PATH="${PATH}:/home/.local/bin:${BINARIES}:/home/go/bin:${TOOLS_NETWORK_VAPT}/neo4j/bin"

COPY --from=ghcr.io/rajanagori/nightingale_web_vapt_image:${IMAGE_TAG} ${TOOLS_WEB_VAPT} ${TOOLS_WEB_VAPT}
COPY --from=ghcr.io/rajanagori/nightingale_web_vapt_image:${IMAGE_TAG} ${GREP_PATTERNS} ${GREP_PATTERNS}
COPY --from=ghcr.io/rajanagori/nightingale_osint_tools_image:${IMAGE_TAG} ${TOOLS_OSINT} ${TOOLS_OSINT}
COPY --from=ghcr.io/rajanagori/nightingale_mobile_vapt_image:${IMAGE_TAG} ${TOOLS_MOBILE_VAPT} ${TOOLS_MOBILE_VAPT}
COPY --from=ghcr.io/rajanagori/nightingale_network_vapt_image:${IMAGE_TAG} ${TOOLS_NETWORK_VAPT} ${TOOLS_NETWORK_VAPT}
COPY --from=ghcr.io/rajanagori/nightingale_forensic_and_red_teaming:${IMAGE_TAG} ${TOOLS_RED_TEAMING} ${TOOLS_RED_TEAMING}
COPY --from=ghcr.io/rajanagori/nightingale_forensic_and_red_teaming:${IMAGE_TAG} ${TOOLS_FORENSICS} ${TOOLS_FORENSICS}
COPY --from=ghcr.io/rajanagori/nightingale_wordlist_image:${IMAGE_TAG} ${WORDLIST} ${WORDLIST}

## Modules stage: Python tools plus vendored binaries. Go tools are installed
## once in the final stage (rebuild-go-binaries.sh) after /home/go is overlaid.
FROM intermediate AS modules

COPY configuration/modules-installation/python-install-modules.sh ${SHELLS}/python-install-modules.sh

RUN set -eux; \
    dos2unix ${SHELLS}/python-install-modules.sh; \
    chmod +x ${SHELLS}/python-install-modules.sh; \
    ln -s ${SHELLS}/python-install-modules.sh /usr/local/bin/python-install-modules; \
    python-install-modules; \
    rm -f ${SHELLS}/python-install-modules.sh

WORKDIR ${BINARIES}
COPY binary/ ${BINARIES}

RUN set -eux; \
    rm -f ${BINARIES}/ttyd ${BINARIES}/xray ${BINARIES}/findomain; \
    chmod +x ${BINARIES}/*; \
    mv ${BINARIES}/* /usr/local/bin/

COPY --chmod=755 configuration/scripts/build-ttyd.sh /tmp/build-ttyd.sh
RUN /tmp/build-ttyd.sh && rm -f /tmp/build-ttyd.sh

## Metasploit stage: setup Metasploit configuration and scripts
FROM modules AS metasploit

WORKDIR ${METASPLOIT_TOOL}
COPY --chmod=644 configuration/msf-configuration/scripts/db.sql .
COPY --chmod=755 configuration/msf-configuration/scripts/init.sh /usr/local/bin/init.sh
COPY --chmod=600 configuration/msf-configuration/conf/database.yml ${METASPLOIT_CONFIG}/metasploit-framework/config/

## Final stage: programming overlay, then the security/rebuild pass
FROM metasploit AS final

ARG IMAGE_TAG
ARG ARCH

WORKDIR /home

COPY configuration/cve-mitigation/vuln-library-purge /tmp/vuln-library-purge
COPY configuration/cve-mitigation/audit-go-binaries.sh \
     configuration/cve-mitigation/rebuild-go-binaries.sh \
     configuration/cve-mitigation/prune-vulnerable-go-binaries.sh \
     configuration/cve-mitigation/install-findomain.sh \
     configuration/cve-mitigation/install-gitleaks.sh \
     configuration/cve-mitigation/install-trufflehog.sh \
     configuration/cve-mitigation/debian-apt-security.sh \
     configuration/cve-mitigation/pip-security-upgrade.sh \
     /usr/local/bin/
COPY --chmod=755 configuration/modules-installation/go-install-modules.sh /usr/local/bin/go-install-modules
COPY configuration/cve-mitigation/go-min-version.txt /usr/local/share/nightingale/go-min-version.txt

RUN set -eux; \
    export DEBIAN_FRONTEND=noninteractive; \
    grep -Ev '^\s*(#|$)' /tmp/vuln-library-purge | while read -r pkg; do \
      if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'; then \
        echo "Purging $pkg"; \
        apt-get purge -y "$pkg" || echo "WARN: purge failed for $pkg (continuing)"; \
      else \
        echo "Skipping $pkg (not installed)"; \
      fi; \
    done; \
    apt-get autoremove -y --purge; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* ; \
    find /usr/share -name "*.md" -delete 2>/dev/null || true; \
    find /usr/share -name "*.txt" -delete 2>/dev/null || true; \
    find /usr/share -name "*.html" -delete 2>/dev/null || true; \
    rm -rf /usr/share/doc/* /usr/share/man/* /usr/share/info/* 2>/dev/null || true; \
    find ${TOOLS_WEB_VAPT} ${TOOLS_OSINT} ${TOOLS_MOBILE_VAPT} ${TOOLS_NETWORK_VAPT} ${TOOLS_RED_TEAMING} ${TOOLS_FORENSICS} ${WORDLIST} -name ".git" -type d -exec rm -rf {} + 2>/dev/null || true;

COPY --from=ghcr.io/rajanagori/nightingale_programming_image:${IMAGE_TAG} /usr/local /usr/local
COPY --from=ghcr.io/rajanagori/nightingale_programming_image:${IMAGE_TAG} /opt/venv3 /opt/venv3
COPY --from=ghcr.io/rajanagori/nightingale_programming_image:${IMAGE_TAG} /usr/local/go /home/go

RUN set -eux; \
    chmod +x /usr/local/bin/debian-apt-security.sh /usr/local/bin/pip-security-upgrade.sh; \
    /usr/local/bin/debian-apt-security.sh; \
    /usr/local/bin/pip-security-upgrade.sh; \
    if command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then \
        ln -s $(which python3) /usr/local/bin/python || \
        ln -s /usr/bin/python3 /usr/local/bin/python || true; \
    fi; \
    if command -v pip3 >/dev/null 2>&1 && ! command -v pip >/dev/null 2>&1; then \
        ln -s $(which pip3) /usr/local/bin/pip || \
        ln -s /usr/bin/pip3 /usr/local/bin/pip || true; \
    fi; \
    command -v python >/dev/null || command -v python3 >/dev/null || { echo "WARNING: Python not found"; }

RUN set -eux; \
    chmod +x /usr/local/bin/prune-vulnerable-go-binaries.sh \
             /usr/local/bin/rebuild-go-binaries.sh \
             /usr/local/bin/go-install-modules \
             /usr/local/bin/install-trufflehog.sh \
             /usr/local/bin/install-findomain.sh \
             /usr/local/bin/install-gitleaks.sh; \
    export TOOLS_WEB_VAPT=/home/tools_web_vapt TOOLS_OSINT=/home/tools_osint \
        TOOLS_NETWORK_VAPT=/home/tools_network_vapt TOOLS_MOBILE_VAPT=/home/tools_mobile_vapt \
        TOOLS_RED_TEAMING=/home/tools_red_teaming TOOLS_FORENSICS=/home/tools_forensics \
        BINARIES=/home/binaries GOPATH=/home/go; \
    /usr/local/bin/prune-vulnerable-go-binaries.sh; \
    /usr/local/bin/rebuild-go-binaries.sh --audit

WORKDIR /home

LABEL org.opencontainers.image.base.name="ghcr.io/rajanagori/nightingale_programming_image:${IMAGE_TAG}" \
      org.opencontainers.image.ref.name="${IMAGE_TAG}" \
      stage="final"
