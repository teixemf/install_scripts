#!/usr/bin/env bash
#
# Script de Instalação/Upgrade PeaNUT Standalone com HTTPS Let's Encrypt (Nginx)
# Este é um script MONOLÍTICO e autónomo.
# Objetivo: Instalar OU atualizar PeaNUT CORRENDO COM UTILIZADOR DE BAIXO PRIVILÉGIO + Configurar HTTPS.
#
# USO: Guarde este ficheiro como 'peanut_installer.sh' no seu LXC Debian 12/13 e execute-o como root.
#
# Modo Automatizado (Instalação/Upgrade com HTTPS):
# chmod +x peanut_installer.sh && ./peanut_installer.sh <DOMÍNIO> <EMAIL> <CF_TOKEN> [production|staging]
#
# Modo Remoção (Cleanup):
# ./peanut_installer.sh -r
#
# Modo Ajuda:
# ./peanut_installer.sh -h
#

# ==============================================================================
# 0. VERIFICAÇÕES PRÉVIAS E DEFINIÇÕES
# ==============================================================================
if [ "$(id -u)" -ne 0 ]; then
    echo "ERRO: Este script deve ser executado como root." >&2
    exit 1
fi

# Variáveis da Aplicação
APP_NAME="PeaNUT"
APP_PORT="3000"
APP_DIR="/opt/peanut"
APP_CONFIG_DIR="/etc/peanut"
APP_CONFIG_FILE="${APP_CONFIG_DIR}/settings.yml"
# Caminho para o executável do Node.js após o build
APP_EXEC_FILE="${APP_DIR}/.next/standalone/server.js"
GITHUB_REPO="Brandawg93/PeaNUT"

# Utilizador e Grupo de baixo privilégio
APP_USER="peanut"
APP_GROUP="peanut"

# Versão do Node.js (requerida pelo PeaNUT)
NODE_VERSION="22"

# ==============================================================================
# 1. FUNÇÕES AUXILIARES E DE LOGGING
# ==============================================================================

# Definições de cor
RD='\e[91m' # Red
GN='\e[92m' # Green
YW='\e[93m' # Yellow
CL='\e[0m'  # Clear
INFO="${YW}[INFO]${CL}"
OK="${GN}[OK]${CL}"
ERROR="${RD}[ERRO]${CL}"

msg_info() { echo -e "${INFO} $*"; }
msg_ok() { echo -e "${OK} $*"; }
msg_error() { echo -e "${ERROR} $*" >&2; }
fatal() { msg_error "$@"; exit 1; }

QUIET_MODE=true
SPINNER_PID=""

start_spinner() {
    (
        local i=1
        local spin='-\|/'
        local delay=0.1
        while :
        do
            local index=$((i % 4))
            printf "\r${INFO} A executar comando... %s" "${spin:index:1}"
            sleep $delay
            i=$((i + 1))
        done
    ) &
    SPINNER_PID=$!
    disown
}

stop_spinner() {
    # Corrigido: Usar 'fi' para fechar 'if'
    if [ -n "$SPINNER_PID" ]; then
        kill "$SPINNER_PID" 2>/dev/null
        wait "$SPINNER_PID" 2>/dev/null
        printf "\r\e[K"
        SPINNER_PID=""
    fi
}

# Wrapper para executar comandos silenciosamente (com spinner) ou verbosamente
run_quietly() {
    local cmd="$1"
    local error_msg="$2"
    local exit_code=0
    
    if $QUIET_MODE; then
        start_spinner
        # Usar eval para lidar corretamente com pipes e redirecionamentos no cmd
        eval "$cmd" >/dev/null 2>&1
        exit_code=$?
        stop_spinner
        if [ $exit_code -ne 0 ]; then
            fatal "$error_msg" 
        fi
    else
        # Executar com output visível
        eval "$cmd" || fatal "$error_msg"
    fi
    return $exit_code
}

catch_errors() {
    set -Eeuo pipefail
    trap 'error_handler $LINENO "$BASH_COMMAND"' ERR
    return 0
}

error_handler() {
    local exit_code="$?"
    local line_number="$1"
    local command="$2"
    
    stop_spinner
    
    if [ "$exit_code" -ne 0 ]; then
        msg_error "Falha na Linha $line_number: Comando '$command' terminou com código $exit_code"
    fi
    exit "$exit_code"
}

show_help() {
    echo "Uso: $0 [OPÇÕES] [DOMÍNIO] [EMAIL] [TOKEN_CLOUDFLARE] [staging|production]"
    echo ""
    echo "Script monolítico para instalar ou atualizar o ${APP_NAME}."
    echo ""
    echo "Opções:"
    echo "  -h, --help        Exibe esta mensagem de ajuda."
    echo "  -r, --remove      Remove completamente a instalação do ${APP_NAME}."
    echo "  -v, --verbose     Ativa o modo verboso (mostra o output dos comandos de instalação)."
    echo ""
    echo "Modo Interativo (Perguntas sobre HTTPS):"
    echo "  $0"
    echo ""
    echo "Modo Automatizado (Com HTTPS):"
    echo "  $0 dominio.pt email@ex.com Token123 [staging|production]"
    echo "  (Se o ambiente [staging|production] for omitido, assume 'production')"
    echo ""
}

# ==============================================================================
# 2. FUNÇÕES DE INSTALAÇÃO/UPGRADE PEANUT
# ==============================================================================

# Função para instalar Node.js 22 e pnpm
setup_nodejs_and_pnpm() {
    msg_info "A configurar o repositório Node.js (Versão ${NODE_VERSION})"
    
    # Adicionar chave GPG do NodeSource
    local NODE_KEYRING="/usr/share/keyrings/nodesource.gpg"
    # Remover chave antiga para evitar conflitos de sobrescrita (idempotente)
    if [ -f "$NODE_KEYRING" ]; then run_quietly "rm -f $NODE_KEYRING" "Falha ao remover a chave GPG antiga do NodeSource."; fi
    run_quietly "curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o $NODE_KEYRING" "Falha ao descarregar a chave GPG do NodeSource."
    
    # 💥 CORREÇÃO DO APT: Usar o formato de repositório de linha única (legacy)
    echo "deb [signed-by=$NODE_KEYRING] https://deb.nodesource.com/node_$NODE_VERSION.x nodistro main" > /etc/apt/sources.list.d/nodesource.list

    run_quietly "apt-get update" "Falha ao atualizar o apt após adicionar o NodeSource."
    run_quietly "apt-get install -y nodejs" "Falha ao instalar o Node.js."
    msg_ok "Node.js ${NODE_VERSION} instalado."

    msg_info "A instalar/atualizar pnpm (via npm)"
    run_quietly "npm install -g pnpm" "Falha ao instalar o pnpm globalmente."
    msg_ok "pnpm instalado."
}


setup_app() {
    msg_info "A atualizar o SO e a instalar utilidades básicas"
    run_quietly "DEBIAN_FRONTEND=noninteractive apt-get update" "Falha ao atualizar o apt."
    
    msg_info "A instalar dependências (nginx, git, curl, wget, python3-venv, cron, openssl, jq, tar, nut-client)"
    # Adicionado 'nut-client' (específico do PeaNUT) e 'python3.11-venv' (fix venv)
    run_quietly "DEBIAN_FRONTEND=noninteractive apt-get install -y nginx git curl python3 python3-pip python3-venv python3.11-venv cron openssl wget jq tar nut-client" "Falha ao instalar dependências."

    run_quietly "DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade" "Falha ao fazer upgrade do sistema."
    msg_ok "Sistema e utilidades atualizadas"

    # --- Instalar Node.js e pnpm ---
    setup_nodejs_and_pnpm

    # --- Criação de Utilizador de Baixo Privilégio ---
    msg_info "A criar utilizador de baixo privilégio para o serviço ${APP_NAME}: ${APP_USER}"
    run_quietly "id -u ${APP_USER} 2>/dev/null || useradd -r -s /bin/false -M -c '${APP_NAME} System User' ${APP_USER}" "Falha ao criar o utilizador ${APP_USER}."
    msg_ok "Utilizador ${APP_USER} criado"
    
    # --- Download e Build do PeaNUT (Source Tarball) ---
    msg_info "A descarregar a última versão do ${APP_NAME} (Tarball de código fonte)"

    local RELEASE_URL
    RELEASE_URL=$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" 2>/dev/null | jq -r '.tag_name')

    if [ -z "$RELEASE_URL" ] || [[ "$RELEASE_URL" == "null" ]]; then
        fatal "Falha Crítica: Não foi possível obter a última versão do ${APP_NAME} no GitHub. Verifique a conectividade."
    else
        msg_info "Última versão do GitHub obtida: ${RELEASE_URL}"
    fi
    
    local DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/archive/refs/tags/${RELEASE_URL}.tar.gz"
    local TEMP_FILE="/tmp/peanut.tar.gz"

    msg_info "URL de download final: ${DOWNLOAD_URL}"
    run_quietly "curl -fsSL ${DOWNLOAD_URL} -o ${TEMP_FILE}" "Falha ao descarregar o código fonte do ${APP_NAME}."
    
    # --- Instalação e Build ---
    msg_info "A instalar e compilar (build) ${APP_NAME}..."
    mkdir -p "$APP_DIR"
    # Limpar diretório antigo para garantir um 'clean build' (como no script original)
    run_quietly "rm -rf ${APP_DIR}/*" "Falha ao limpar o diretório de instalação antigo."
    # --strip-components=1 remove a pasta de topo (ex: PeaNUT-vX.X.X/) do tarball
    run_quietly "tar -xzf ${TEMP_FILE} -C ${APP_DIR} --strip-components=1" "Falha ao extrair o código fonte."
    run_quietly "rm -f ${TEMP_FILE}" ""
    
    # Executar comandos de build como root (necessário para instalar dependências)
    run_quietly "cd ${APP_DIR} && pnpm i" "Falha ao executar 'pnpm install'."
    run_quietly "cd ${APP_DIR} && pnpm run build:local" "Falha ao executar 'pnpm run build:local'."
    
    # Preparar ficheiros de produção
    run_quietly "cp -r ${APP_DIR}/.next/static ${APP_DIR}/.next/standalone/.next/" "Falha ao copiar ficheiros estáticos pós-build."
    msg_ok "${APP_NAME} ${RELEASE_URL} instalado e compilado em ${APP_DIR}"

    # --- Configuração ---
    msg_info "A configurar ${APP_NAME}"
    mkdir -p "$APP_CONFIG_DIR"
    mkdir -p "${APP_DIR}/.next/standalone/config"
    
    # Criar ficheiro de configuração (APENAS se não existir)
    if [ ! -f "$APP_CONFIG_FILE" ]; then
        cat <<EOF >"$APP_CONFIG_FILE"
WEB_HOST: 0.0.0.0
WEB_PORT: ${APP_PORT}
NUT_HOST: 127.0.0.1
NUT_PORT: 3493
EOF
    else
        msg_info "${APP_CONFIG_FILE} existente detetado. A manter configurações."
    fi
    
    # Ligar (link) a configuração
    run_quietly "ln -sf ${APP_CONFIG_FILE} ${APP_DIR}/.next/standalone/config/settings.yml" "Falha ao criar o link simbólico da configuração."

    # --- Definir Permissões para o Utilizador de Baixo Privilégio ---
    run_quietly "chown -R ${APP_USER}:${APP_GROUP} ${APP_DIR}" "Falha ao definir permissões em ${APP_DIR}."
    run_quietly "chown -R ${APP_USER}:${APP_GROUP} ${APP_CONFIG_DIR}" "Falha ao definir permissões em ${APP_CONFIG_DIR}."
    msg_ok "Propriedade dos ficheiros ajustada para o utilizador ${APP_USER}"

    # --- Configurar Serviço Systemd ---
    msg_info "A configurar e iniciar o serviço Systemd com utilizador ${APP_USER}"
    cat <<EOF >/etc/systemd/system/peanut.service
[Unit]
Description=PeaNUT - A Web Client for NUT
Documentation=https://github.com/Brandawg93/PeaNUT/
After=network.target
[Service]
SyslogIdentifier=peanut
Restart=always
RestartSec=5
Type=simple
Environment="NODE_ENV=production"
# O utilizador 'peanut' corre o serviço
User=${APP_USER}
Group=${APP_GROUP}
WorkingDirectory=${APP_DIR}
# O ExecStart usa o 'node' instalado globalmente
ExecStart=/usr/bin/node ${APP_EXEC_FILE}
TimeoutStopSec=30
[Install]
WantedBy=multi-user.target
EOF
    
    run_quietly "systemctl daemon-reload" "Falha ao recarregar a configuração do Systemd."
    run_quietly "systemctl stop peanut 2>/dev/null" "A tentar parar o serviço (ignorar se falhar)."
    run_quietly "systemctl enable peanut" "Falha ao ativar o serviço ${APP_NAME}."
    run_quietly "systemctl restart peanut" "Falha ao iniciar/reiniciar o serviço ${APP_NAME}. Verifique o log (journalctl -u peanut)."
    msg_ok "Serviço ${APP_NAME} ativo, a correr como ${APP_USER} na porta ${APP_PORT}"
}

# ==============================================================================
# 3. FUNÇÃO DE REMOÇÃO COMPLETA
# ==============================================================================

remove_app_components() {
    msg_info "A iniciar o processo de remoção COMPLETA do ${APP_NAME}..."

    # 1. Parar e Desativar o Serviço
    if systemctl is-active --quiet peanut; then
        msg_info "A parar o serviço peanut..."
        run_quietly "systemctl stop peanut" "Falha ao parar o serviço ${APP_NAME}."
    fi
    if systemctl is-enabled --quiet peanut; then
        msg_info "A desativar o serviço peanut..."
        run_quietly "systemctl disable peanut" "Falha ao desativar o serviço ${APP_NAME}."
    fi
    run_quietly "rm -f /etc/systemd/system/peanut.service" "Falha ao remover ficheiro de serviço."
    run_quietly "systemctl daemon-reload" "Falha ao recarregar Systemd."
    msg_ok "Serviço ${APP_NAME} removido."

    # 2. Limpar Ficheiros e Diretórios
    msg_info "A remover diretórios de aplicação e configuração..."
    run_quietly "rm -rf ${APP_DIR}" "Falha ao remover diretório de dados ${APP_DIR}."
    run_quietly "rm -rf ${APP_CONFIG_DIR}" "Falha ao remover diretório de configuração ${APP_CONFIG_DIR}."
    msg_ok "Ficheiros de dados do ${APP_NAME} removidos."

    # 3. Remover Utilizador (se existir)
    if id -u "$APP_USER" &>/dev/null; then
        msg_info "A remover utilizador de sistema ${APP_USER}..."
        run_quietly "userdel ${APP_USER}" "Falha ao remover utilizador ${APP_USER}."
        msg_ok "Utilizador ${APP_USER} removido."
    fi
    
    # 4. Limpar Node.js e pnpm (Opcional, mas recomendado para remoção completa)
    msg_info "A remover Node.js e pnpm..."
    run_quietly "npm uninstall -g pnpm" "Falha ao remover pnpm."
    run_quietly "apt-get purge -y nodejs" "Falha ao purgar nodejs."
    run_quietly "rm -f /etc/apt/sources.list.d/nodesource.list" ""
    run_quietly "rm -f /usr/share/keyrings/nodesource.gpg" ""
    msg_ok "Node.js e pnpm removidos."

    # 5. Limpar Configuração Nginx e Certbot
    msg_info "A limpar configuração Nginx e Certbot..."
    run_quietly "rm -f /etc/nginx/sites-available/peanut" ""
    run_quietly "rm -f /etc/nginx/sites-enabled/peanut" ""
    run_quietly "rm -f /etc/nginx/sites-enabled/default" "" 
    
    if [ -d "/opt/certbot-cf-venv" ]; then
        msg_info "A remover ambiente virtual Certbot e credenciais Cloudflare..."
        run_quietly "rm -rf /opt/certbot-cf-venv" ""
        run_quietly "rm -rf /root/.secrets" ""
        CRON_CONTENT=$(crontab -l 2>/dev/null || echo "")
        (echo "$CRON_CONTENT" | grep -v 'certbot renew') | crontab - || msg_error "Falha ao limpar cron job."
    fi
    
    # 6. Reiniciar Nginx
    if systemctl is-active --quiet nginx; then
        run_quietly "systemctl restart nginx" "Falha ao reiniciar Nginx."
    fi
    
    msg_ok "Limpeza do sistema concluída."
    
    echo ""
    echo -e "${GN}====================================================================${CL}"
    echo -e "${GN}REMOÇÃO CONCLUÍDA. O servidor está limpo de componentes ${APP_NAME}.${CL}"
    echo -e "${GN}Dependências como 'nut-client' podem requerer remoção manual:${CL}"
    echo -e "${YW}apt-get autoremove --purge nut-client${CL}"
    echo -e "${GN}====================================================================${CL}"
}


# ==============================================================================
# 4. CONFIGURAÇÃO HTTPS (Certbot/Cloudflare - Usando Nginx)
# ==============================================================================

setup_https() {
    local CLI_DOMAIN="$1"
    local CLI_EMAIL="$2"
    local CLI_CF_TOKEN="$3"
    local CLI_ENV="${4:-production}"

    local DOMAIN
    local EMAIL
    local CF_TOKEN
    local LE_ENV
    local LE_SERVER_ARG=""
    local USE_HTTPS="n"
    
    # Verificar se os argumentos CLI para HTTPS foram passados
    if [[ -n "$CLI_DOMAIN" && -n "$CLI_EMAIL" && -n "$CLI_CF_TOKEN" ]]; then
        msg_info "Parâmetros HTTPS detetados na CLI. A configurar HTTPS automaticamente."
        USE_HTTPS="y"
        DOMAIN="$CLI_DOMAIN"
        EMAIL="$CLI_EMAIL"
        CF_TOKEN="$CLI_CF_TOKEN"
        LE_ENV="$CLI_ENV"
        
        if [[ "$LE_ENV" == "staging" ]]; then
            LE_SERVER_ARG="--staging"
            msg_info "AVISO: A usar ambiente Let's Encrypt de TESTE (staging)."
        else
            LE_ENV="production"
            msg_info "A usar ambiente Let's Encrypt de PRODUÇÃO."
        fi
    else
        # Se os argumentos não foram passados, perguntar interativamente
        echo ""
        read -r -p "Deseja configurar HTTPS com Let's Encrypt (Cloudflare DNS)? [y/N]: " USE_HTTPS
        USE_HTTPS=$(echo "$USE_HTTPS" | tr '[:upper:]' '[:lower:]')

        if [[ "$USE_HTTPS" != "y" ]]; then
            msg_info "A configurar apenas HTTP. Pode configurar HTTPS mais tarde."
            configure_nginx_http
            return
        fi
        
        # Coletar Informação Interativamente
        msg_info "--- Configuração HTTPS (Let's Encrypt / Cloudflare) ---"
        read -r -p "Introduza o seu domínio (ex: peanut.o-seu-dominio.pt): " DOMAIN
        read -r -p "Introduza o seu e-mail (para avisos de renovação): " EMAIL
        echo ""
        read -r -p "Introduza o seu API Token da Cloudflare (com permissão DNS-Edit): " CF_TOKEN
        echo ""
        read -r -p "Usar ambiente de Produção (P) ou Staging/Teste (S)? [P/s]: " LE_ENV_CHOICE
        LE_ENV_CHOICE=$(echo "$LE_ENV_CHOICE" | tr '[:upper:]' '[:lower:]')
        
        if [[ "$LE_ENV_CHOICE" == "s" ]]; then
            LE_SERVER_ARG="--staging"
            LE_ENV="staging"
            msg_info "AVISO: Usar Staging é útil para testes. O certificado NÃO será válido publicamente."
        else
            LE_ENV="production"
            msg_info "A usar ambiente de PRODUÇÃO (Certificado válido)."
        fi
    fi
    
    if [[ -z "$DOMAIN" || -z "$EMAIL" || -n "$CF_TOKEN" ]]; then
        # 💥 Correção V19: O CF_TOKEN não pode ser vazio para CLI, mas a verificação interativa é feita acima
        if [[ "$USE_HTTPS" == "y" ]]; then
             if [[ -z "$CF_TOKEN" ]]; then
                fatal "Domínio, E-mail ou Cloudflare Token não podem estar vazios."
             fi
        fi
    fi
    
    msg_info "A instalar Certbot e Plugin Cloudflare no ambiente virtual"
    
    # Bloco Try/Catch para a criação do VENV (baseado na nossa experiência anterior)
    if ! python3 -m venv /opt/certbot-cf-venv 2>/dev/null; then
        msg_error "Falha ao criar venv (tentativa 1). A forçar instalação de python3-venv e python3.11-venv..."
        run_quietly "apt-get install -y python3-venv python3.11-venv" "Falha ao instalar python3-venv / python3.11-venv."
        
        python3.11 -m venv /opt/certbot-cf-venv || fatal "Falha crítica ao criar o ambiente virtual Python."
    fi
    
    source /opt/certbot-cf-venv/bin/activate
    
    run_quietly "pip install certbot certbot-dns-cloudflare" "Falha ao instalar Certbot/Plugin."
    msg_ok "Certbot e Plugin Cloudflare instalados"

    CF_CRED_FILE="/root/.secrets/cloudflare_credentials.ini"
    mkdir -p /root/.secrets
    
    cat <<EOF >"$CF_CRED_FILE"
dns_cloudflare_api_token = $CF_TOKEN
EOF
    chmod 600 "$CF_CRED_FILE" # Permissões restritas

    # 💥 CORREÇÃO DA INTERATIVIDADE: Usar --non-interactive e '|| true' para evitar que o script pare
    msg_info "A tentar limpar registos de certificados antigos (se existirem)..."
    # Adicionar --non-interactive para forçar a confirmação da eliminação de certificados staging/antigos
    /opt/certbot-cf-venv/bin/certbot delete --cert-name "$DOMAIN" --non-interactive 2>/dev/null || true
    msg_ok "Verificação de limpeza concluída."


    msg_info "A emitir certificado Let's Encrypt para $DOMAIN (Ambiente: ${LE_ENV})..."
    
    local certbot_cmd="/opt/certbot-cf-venv/bin/certbot certonly \
            --dns-cloudflare \
            --dns-cloudflare-credentials \"$CF_CRED_FILE\" \
            --email \"$EMAIL\" \
            --domains \"$DOMAIN\" \
            --agree-tos \
            --non-interactive \
            --cert-name \"$DOMAIN\" \
            $LE_SERVER_ARG"

    local certbot_error_msg="Falha na emissão do certificado. Verifique as credenciais e o DNS."

    if $QUIET_MODE; then
        start_spinner
        eval "$certbot_cmd" >/dev/null 2>&1
        local certbot_exit_code=$?
        stop_spinner
    else
        eval "$certbot_cmd"
        local certbot_exit_code=$?
    fi

    if [ $certbot_exit_code -ne 0 ]; then
        msg_error "$certbot_error_msg"
        deactivate 2>/dev/null
        configure_nginx_http 
        return
    fi
    
    msg_ok "Certificado Let's Encrypt emitido com sucesso!"
    deactivate 2>/dev/null

    configure_nginx_https "$DOMAIN"
    
    msg_info "A configurar renovação automática do certificado"
    CRON_CONTENT=$(crontab -l 2>/dev/null || echo "")
    (echo "$CRON_CONTENT" | grep -v 'certbot renew'; echo "0 3 * * * /opt/certbot-cf-venv/bin/certbot renew --quiet --nginx") | crontab - || fatal "Falha ao definir o cron job."
    msg_ok "Renovação automática configurada."
}

# ==============================================================================
# 5. CONFIGURAÇÃO NGINX (HTTP/HTTPS Reverse Proxy)
# ==============================================================================

configure_nginx_http() {
    msg_info "A configurar Nginx como proxy reverso HTTP padrão"
    
    cat <<EOF >/etc/nginx/sites-available/peanut
server {
    listen 80;
    listen [::]:80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF
    run_quietly "rm -f /etc/nginx/sites-enabled/default" "Falha ao remover o site padrão do Nginx."
    run_quietly "rm -f /etc/nginx/sites-enabled/peanut" ""
    run_quietly "ln -sf /etc/nginx/sites-available/peanut /etc/nginx/sites-enabled/peanut" "Falha ao ativar o site ${APP_NAME}."
    run_quietly "nginx -t" "Falha na sintaxe do Nginx. Verifique o log."
    run_quietly "systemctl restart nginx" "Falha ao reiniciar o Nginx."
    msg_ok "Nginx configurado para HTTP na porta 80 e a encaminhar para o ${APP_NAME}."
}

configure_nginx_https() {
    local DOMAIN="$1"
    local CERT_PATH="/etc/letsencrypt/live/$DOMAIN"
    
    msg_info "A configurar Nginx para HTTPS (Porta 443) e Redirecionamento"

    cat <<EOF >/etc/nginx/sites-available/peanut
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;

    ssl_certificate ${CERT_PATH}/fullchain.pem;
    ssl_certificate_key ${CERT_PATH}/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers on;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

    location / {
        proxy_pass http://127.0.0.1:${APP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF
    run_quietly "rm -f /etc/nginx/sites-enabled/default" ""
    run_quietly "rm -f /etc/nginx/sites-enabled/peanut" ""
    run_quietly "ln -sf /etc/nginx/sites-available/peanut /etc/nginx/sites-enabled/peanut" "Falha ao ativar o site ${APP_NAME}."
    
    run_quietly "nginx -t" "Falha na sintaxe do Nginx após configurar HTTPS."
    run_quietly "systemctl restart nginx" "Falha ao reiniciar o Nginx."
    msg_ok "Nginx configurado para HTTPS (Porta 443) e REINICIADO."
}

# ==============================================================================
# 6. FLUXO PRINCIPAL
# ==============================================================================

main() {
    catch_errors
    
    local CLI_DOMAIN=""
    local CLI_EMAIL=""
    local CLI_CF_TOKEN=""
    local CLI_ENV=""
    local args=()
    local REMOVE_MODE=false
    local arg
    
    # Processar flags primeiro
    for arg in "$@"; do
        case "$arg" in
            -v|--verbose)
                QUIET_MODE=false
                ;;
            -r|--remove)
                REMOVE_MODE=true
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                # Adicionar argumentos posicionais
                if [[ ! "$arg" =~ ^- ]]; then
                    args+=("$arg")
                fi
                ;;
        esac 
    done

    # Ativar modo verboso se não estiver quieto
    if ! $QUIET_MODE; then
        msg_info "Modo VERBOSO ativado."
    fi

    if $REMOVE_MODE; then
        remove_app_components
        exit 0
    fi

    # Mapear argumentos posicionais
    CLI_DOMAIN="${args[0]:-}"
    CLI_EMAIL="${args[1]:-}"
    CLI_CF_TOKEN="${args[2]:-}"
    CLI_ENV="${args[3]:-}"
    
    # Se nenhum argumento posicional ou flag for passado, mostrar ajuda (e permitir modo interativo)
    if [[ ${#args[@]} -eq 0 && $QUIET_MODE == true && $REMOVE_MODE == false ]]; then
        show_help
        
        # Permitir que o utilizador decida se quer continuar interativamente
        read -r -p "Nenhum argumento fornecido. Deseja continuar em modo interativo? [Y/n]: " CONTINUE_INTERACTIVE
        CONTINUE_INTERACTIVE=$(echo "$CONTINUE_INTERACTIVE" | tr '[:upper:]' '[:lower:]')
        if [[ "$CONTINUE_INTERACTIVE" == "n" ]]; then
            exit 0
        fi
    fi
    
    # 1. Instalar/Atualizar PeaNUT e Dependências (com novo utilizador)
    setup_app

    # 2. Configurar HTTPS (ou apenas HTTP)
    setup_https "$CLI_DOMAIN" "$CLI_EMAIL" "$CLI_CF_TOKEN" "$CLI_ENV"
    
    msg_info "A limpar o sistema"
    run_quietly "DEBIAN_FRONTEND=noninteractive apt-get -y autoremove" "Falha during autoremove."
    run_quietly "DEBIAN_FRONTEND=noninteractive apt-get -y autoclean" "Falha during autoclean."
    
    echo ""
    echo -e "${GN}====================================================================${CL}"
    msg_ok "INSTALAÇÃO DO ${APP_NAME} CONCLUÍDA COM SUCESSO!"
    
    if [[ -n "$CLI_DOMAIN" ]]; then
        echo -e "A aplicação deve estar acessível via HTTPS em: ${YW}https://${CLI_DOMAIN}${CL}"
    else
        echo -e "A aplicação deve estar acessível via HTTP em: ${YW}http://<IP_DO_LXC>:${APP_PORT}${CL} (ou ${YW}http://<IP_DO_LXC>${CL} se Nginx for a única app a correr na porta 80)."
    fi

    echo -e "O serviço está a correr de forma segura com o utilizador: ${YW}${APP_USER}${CL}"
    echo -e "${GN}====================================================================${CL}"
}

# INÍCIO
main "$@"
