#!/usr/bin/env bash
#
# Script de Instalação/Upgrade Ansible Semaphore Standalone com HTTPS Let's Encrypt (Nginx)
# Este é um script MONOLÍTICO e autónomo.
# Objetivo: Instalar OU atualizar Semaphore CORRENDO COM UTILIZADOR DE BAIXO PRIVILÉGIO + Configurar HTTPS.
#
# USO: Guarde este ficheiro como 'semaphore-monolito.sh' no seu LXC Debian 12/13 e execute-o como root.
#
# Modo Automatizado (Instalação/Upgrade com HTTPS):
# chmod +x semaphore-monolito.sh && ./semaphore-monolito.sh <DOMÍNIO> <EMAIL> <CF_TOKEN> [production|staging]
#
# Modo Remoção (Cleanup):
# ./semaphore-monolito.sh -r
#

# ==============================================================================
# 0. VERIFICAÇÕES PRÉVIAS E DEFINIÇÕES
# ==============================================================================
if [ "$(id -u)" -ne 0 ]; then
    echo "ERRO: Este script deve ser executado como root." >&2
    exit 1
fi

# Variáveis do Semaphore
SEM_PORT="3000"
SEM_DIR="/opt/semaphore"
SEM_BIN="/usr/local/bin/semaphore"

# NOVO: Utilizador e Grupo de baixo privilégio para correr o serviço
SEM_USER="semaphore"
SEM_GROUP="semaphore"

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
    if [ -n "$SPINNER_PID" ]; then
        kill "$SPINNER_PID" 2>/dev/null
        wait "$SPINNER_PID" 2>/dev/null
        printf "\r\e[K"
        SPINNER_PID=""
    fi
}

run_quietly() {
    local cmd="$1"
    local error_msg="$2"
    local exit_code=0
    
    if $QUIET_MODE; then
        start_spinner
        eval "$cmd" >/dev/null 2>&1
        exit_code=$?
        stop_spinner
        if [ $exit_code -ne 0 ]; then
            fatal "$error_msg" 
        fi
    else
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

# ==============================================================================
# 2. FUNÇÕES DE INSTALAÇÃO/UPGRADE SEMAPHORE
# ==============================================================================

setup_semaphore() {
    msg_info "A atualizar o SO e a instalar utilidades básicas"
    run_quietly "DEBIAN_FRONTEND=noninteractive apt-get update" "Falha ao atualizar o apt."
    
    msg_info "A instalar dependências (nginx, git, curl, wget, python3-venv, cron, openssl, jq, tar)"
    run_quietly "DEBIAN_FRONTEND=noninteractive apt-get install -y nginx git curl python3 python3-pip python3-venv cron openssl wget jq tar" "Falha ao instalar dependências."

    run_quietly "DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade" "Falha ao fazer upgrade do sistema."
    msg_ok "Sistema e utilidades atualizadas"

    # --- Criação de Utilizador de Baixo Privilégio ---
    msg_info "A criar utilizador de baixo privilégio para o serviço Semaphore: ${SEM_USER}"
    # Criação do utilizador sem shell de login e sem diretório home
    run_quietly "id -u ${SEM_USER} 2>/dev/null || useradd -r -s /bin/false -M -c 'Semaphore System User' ${SEM_USER}" "Falha ao criar o utilizador ${SEM_USER}."
    msg_ok "Utilizador ${SEM_USER} criado"
    
    # --- Instalar Ansible ---
    msg_info "A configurar e instalar Ansible (via repositório PPA no Debian/Ubuntu)"
    local ANSIBLE_KEYRING="/usr/share/keyrings/ansible-archive-keyring.gpg"
    if [ -f "$ANSIBLE_KEYRING" ]; then run_quietly "rm -f $ANSIBLE_KEYRING" "Falha ao remover a chave GPG antiga."; fi
    run_quietly "wget -q -O - 'https://keyserver.ubuntu.com/pks/lookup?fingerprint=on&op=get&search=0x6125E2A8C77F2818FB7BD15B93C4A3FD7BB9C367' | gpg --dearmor -o $ANSIBLE_KEYRING" "Falha ao descarregar a chave GPG do Ansible."
    cat <<EOF >/etc/apt/sources.list.d/ansible.sources
Types: deb
URIs: http://ppa.launchpad.net/ansible/ansible/ubuntu
Suites: jammy
Components: main
Signed-By: $ANSIBLE_KEYRING
EOF
    run_quietly "apt update" "Falha ao atualizar a lista de pacotes após adicionar o PPA do Ansible."
    run_quietly "apt install -y ansible" "Falha ao instalar o pacote Ansible."
    msg_ok "Ansible instalado"

    # --- Download e Deploy do Semaphore Binary ---
    msg_info "A descarregar a última versão do binário do Semaphore"

    local RELEASE_URL
    RELEASE_URL=$(curl -fsSL "https://api.github.com/repos/semaphoreui/semaphore/releases/latest" 2>/dev/null | jq -r '.tag_name')

    if [ -z "$RELEASE_URL" ] || [[ "$RELEASE_URL" == "null" ]]; then
        # O utilizador solicitou que o script pare e emita um erro em vez de usar uma versão de fallback.
        fatal "Falha Crítica: Não foi possível obter a última versão do Semaphore no GitHub. Por favor, verifique a sua conectividade ou as permissões de rede."
    else
        msg_info "Última versão do GitHub obtida: ${RELEASE_URL}"
    fi
    
    local SEM_ARCH="linux-amd64" 
    local BINARY_NAME="semaphore"
    local DOWNLOAD_URL
    local TEMP_FILE="/tmp/semaphore_downloaded"
    local EXTRACT_DIR="/tmp/semaphore_extract"

    
    # CORREÇÃO CRÍTICA DO ERRO 404 (para a versão v2.16.32)
    if [[ "$RELEASE_URL" == "v2.16.32" ]]; then
        DOWNLOAD_URL="https://github.com/semaphoreui/semaphore/releases/download/v2.16.32/semaphore_2.16.32_linux_amd64.tar.gz"
        msg_info "Versão v2.16.32 detetada. A usar ficheiro .tar.gz e a extrair o binário."
    else
        DOWNLOAD_URL="https://github.com/semaphoreui/semaphore/releases/download/${RELEASE_URL}/semaphore-latest-${SEM_ARCH}"
    fi

    msg_info "URL de download final: ${DOWNLOAD_URL}"

    if curl -fsSL "${DOWNLOAD_URL}" -o "${TEMP_FILE}"; then
        msg_ok "Ficheiro de instalação do Semaphore descarregado com sucesso!"
    else
        fatal "Falha ao descarregar o binário do Semaphore. Verifique a conectividade e a URL: ${DOWNLOAD_URL}"
    fi
    
    if [[ "$RELEASE_URL" == "v2.16.32" ]]; then
        msg_info "A extrair o binário 'semaphore' do .tar.gz"
        mkdir -p "$EXTRACT_DIR"
        if tar -xzf "${TEMP_FILE}" -C "$EXTRACT_DIR"; then
            run_quietly "mv ${EXTRACT_DIR}/${BINARY_NAME} ${SEM_BIN}" "Falha ao mover o binário extraído para ${SEM_BIN}."
            run_quietly "rm -rf ${EXTRACT_DIR}" ""
            run_quietly "rm -f ${TEMP_FILE}" ""
        else
            fatal "Falha ao extrair o binário do ficheiro .tar.gz."
        fi
    else
        run_quietly "mv ${TEMP_FILE} ${SEM_BIN}" "Falha ao mover o binário para ${SEM_BIN}."
    fi

    run_quietly "chmod +x ${SEM_BIN}" "Falha ao dar permissões de execução ao binário."
    msg_ok "Semaphore ${RELEASE_URL} descarregado e instalado em ${SEM_BIN}"

    # --- Configuração Inicial ---
    msg_info "A configurar o Semaphore"
    mkdir -p "$SEM_DIR"

    # --- DEFINIR PROPRIEDADE DA PASTA PARA O NOVO UTILIZADOR ---
    run_quietly "chown -R ${SEM_USER}:${SEM_GROUP} ${SEM_DIR}" "Falha ao definir permissões em ${SEM_DIR}."
    msg_ok "Propriedade de ${SEM_DIR} ajustada para o utilizador ${SEM_USER}"

    # Gerar chaves de segurança aleatórias (APENAS se config.json não existir)
    local SEM_HASH
    local SEM_ENCRYPTION
    local SEM_KEY
    local SEM_PW
    
    if [ ! -f "$SEM_DIR/config.json" ]; then
        SEM_HASH=$(openssl rand -base64 32)
        SEM_ENCRYPTION=$(openssl rand -base64 32)
        SEM_KEY=$(openssl rand -base64 32)
        
        cat <<EOF >"$SEM_DIR/config.json"
{
  "bolt": {
    "host": "${SEM_DIR}/semaphore_db.bolt"
  },
  "tmp_path": "${SEM_DIR}/tmp",
  "cookie_hash": "${SEM_HASH}",
  "cookie_encryption": "${SEM_ENCRYPTION}",
  "access_key_encryption": "${SEM_KEY}",
  "port": "${SEM_PORT}"
}
EOF
    else
        msg_info "config.json existente detetado. A manter configurações e chaves."
    fi
    
    # Criar utilizador Administrador (apenas se a DB não existir)
    if [ ! -f "$SEM_DIR/semaphore_db.bolt" ]; then
        msg_info "A criar utilizador administrador inicial"
        SEM_PW=$(openssl rand -base64 12)
        
        # O comando de adição de utilizador é executado com o utilizador de baixo privilégio
        local USER_ADD_CMD="${SEM_BIN} user add --admin --login admin --email admin@localhost.com --name Administrator --password \"${SEM_PW}\" --config ${SEM_DIR}/config.json"
        
        run_quietly "su -s /bin/sh ${SEM_USER} -c \"(cd ${SEM_DIR} && ${USER_ADD_CMD})\"" "Falha ao criar o utilizador administrador"
        
        echo "A password do utilizador 'admin' inicial é: ${SEM_PW}" > ~/semaphore_admin_password.txt
        msg_ok "Utilizador administrador criado. A password foi guardada em ~/semaphore_admin_password.txt"
    else
        msg_ok "Base de dados BoltDB existente detetada. A ignorar criação de utilizador."
    fi

    # --- Configurar Serviço Systemd ---
    msg_info "A configurar e iniciar o serviço Systemd com utilizador ${SEM_USER}"
    cat <<EOF >/etc/systemd/system/semaphore.service
[Unit]
Description=Semaphore UI for Ansible
Documentation=https://docs.semaphoreui.com/
After=network.target

[Service]
Type=simple
# CORRER COM UTILIZADOR DE BAIXO PRIVILÉGIO
User=${SEM_USER}
Group=${SEM_GROUP}
WorkingDirectory=${SEM_DIR}
ExecStart=${SEM_BIN} server --config ${SEM_DIR}/config.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    
    run_quietly "systemctl daemon-reload" "Falha ao recarregar a configuração do Systemd."
    run_quietly "systemctl stop semaphore 2>/dev/null" "A tentar parar o serviço (ignorar se falhar)."
    run_quietly "systemctl enable semaphore" "Falha ao ativar o serviço Semaphore."
    run_quietly "systemctl restart semaphore" "Falha ao iniciar/reiniciar o serviço Semaphore. Verifique o log (journalctl -u semaphore)."
    msg_ok "Serviço Semaphore ativo, a correr como ${SEM_USER} na porta ${SEM_PORT}"
}

# ==============================================================================
# 3. FUNÇÃO DE REMOÇÃO COMPLETA
# ==============================================================================

remove_semaphore_components() {
    msg_info "A iniciar o processo de remoção COMPLETA do Semaphore..."

    # 1. Parar e Desativar o Serviço
    if systemctl is-active --quiet semaphore; then
        msg_info "A parar o serviço semaphore..."
        run_quietly "systemctl stop semaphore" "Falha ao parar o serviço Semaphore."
    fi
    if systemctl is-enabled --quiet semaphore; then
        msg_info "A desativar o serviço semaphore..."
        run_quietly "systemctl disable semaphore" "Falha ao desativar o serviço Semaphore."
    fi
    run_quietly "rm -f /etc/systemd/system/semaphore.service" "Falha ao remover ficheiro de serviço."
    run_quietly "systemctl daemon-reload" "Falha ao recarregar Systemd."
    msg_ok "Serviço Semaphore removido."

    # 2. Limpar Ficheiros e Diretórios
    msg_info "A remover binário e pastas de configuração..."
    run_quietly "rm -f ${SEM_BIN}" "Falha ao remover binário Semaphore."
    run_quietly "rm -rf ${SEM_DIR}" "Falha ao remover diretório de dados ${SEM_DIR}."
    run_quietly "rm -f ~/semaphore_admin_password.txt" ""
    msg_ok "Ficheiros de dados do Semaphore removidos."

    # 3. Remover Utilizador (se existir)
    if id -u "$SEM_USER" &>/dev/null; then
        msg_info "A remover utilizador de sistema ${SEM_USER}..."
        run_quietly "userdel ${SEM_USER}" "Falha ao remover utilizador ${SEM_USER}."
        msg_ok "Utilizador ${SEM_USER} removido."
    fi

    # 4. Limpar Configuração Nginx e Certbot
    msg_info "A limpar configuração Nginx e Certbot..."
    run_quietly "rm -f /etc/nginx/sites-available/semaphore" ""
    run_quietly "rm -f /etc/nginx/sites-enabled/semaphore" ""
    run_quietly "rm -f /etc/nginx/sites-enabled/default" "" 
    
    if [ -d "/opt/certbot-cf-venv" ]; then
        msg_info "A remover ambiente virtual Certbot e credenciais Cloudflare..."
        run_quietly "rm -rf /opt/certbot-cf-venv" ""
        run_quietly "rm -rf /root/.secrets" ""
        CRON_CONTENT=$(crontab -l 2>/dev/null || echo "")
        (echo "$CRON_CONTENT" | grep -v 'certbot renew') | crontab - || msg_error "Falha ao limpar cron job."
    fi
    
    # 5. Reiniciar Nginx
    if systemctl is-active --quiet nginx; then
        run_quietly "systemctl restart nginx" "Falha ao reiniciar Nginx."
    fi
    
    msg_ok "Limpeza do sistema concluída."
    
    echo ""
    echo -e "${GN}====================================================================${CL}"
    echo -e "${GN}REMOÇÃO CONCLUÍDA. O servidor está limpo de componentes Semaphore.${CL}"
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
    
    if [[ -n "$CLI_DOMAIN" && -n "$CLI_EMAIL" && -n "$CLI_CF_TOKEN" ]]; then
        msg_info "Parâmetros HTTPS detetados na CLI. A configurar HTTPS automaticamente."
        USE_HTTPS="y"
        DOMAIN="$CLI_DOMAIN"
        EMAIL="$CLI_EMAIL"
        CF_TOKEN="$CLI_CF_TOKEN"
        LE_ENV="$CLI_ENV"
        
        if [[ "$LE_ENV" == "staging" ]]; then
            LE_SERVER_ARG="--staging"
        else
            LE_ENV="production"
        fi
    else
        msg_info "A configurar apenas HTTP (Modo interativo não suportado neste script monolítico simplificado)."
        configure_nginx_http
        return
    fi
    
    # A linha problemática foi removida.
    
    if [[ -z "$DOMAIN" || -z "$EMAIL" || -z "$CF_TOKEN" ]]; then
        fatal "Domínio, E-mail ou Cloudflare Token não podem estar vazios."
    fi
    
    msg_info "A instalar Certbot e Plugin Cloudflare no ambiente virtual"
    python3 -m venv /opt/certbot-cf-venv || fatal "Falha ao criar o ambiente virtual Python."
    source /opt/certbot-cf-venv/bin/activate
    
    run_quietly "pip install certbot certbot-dns-cloudflare" "Falha ao instalar Certbot/Plugin."
    msg_ok "Certbot e Plugin Cloudflare instalados"

    CF_CRED_FILE="/root/.secrets/cloudflare_credentials.ini"
    mkdir -p /root/.secrets
    
    cat <<EOF >"$CF_CRED_FILE"
dns_cloudflare_api_token = $CF_TOKEN
EOF
    chmod 600 "$CF_CRED_FILE"

    msg_info "A emitir certificado Let's Encrypt para $DOMAIN (Ambiente: ${LE_ENV})..."
    
    local certbot_cmd="/opt/certbot-cf-venv/bin/certbot certonly \
            --dns-cloudflare \
            --dns-cloudflare-credentials \"$CF_CRED_FILE\" \
            --email \"$EMAIL\" \
            --domains \"$DOMAIN\" \
            --agree-tos \
            --non-interactive \
            --force-renewal \
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
    
    cat <<EOF >/etc/nginx/sites-available/semaphore
server {
    listen 80;
    listen [::]:80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:${SEM_PORT};
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
    run_quietly "rm -f /etc/nginx/sites-enabled/semaphore" ""
    run_quietly "ln -sf /etc/nginx/sites-available/semaphore /etc/nginx/sites-enabled/semaphore" "Falha ao ativar o site Semaphore."
    run_quietly "nginx -t" "Falha na sintaxe do Nginx. Verifique o log."
    run_quietly "systemctl restart nginx" "Falha ao reiniciar o Nginx."
    msg_ok "Nginx configurado para HTTP na porta 80 e a encaminhar para o Semaphore."
}

configure_nginx_https() {
    local DOMAIN="$1"
    local CERT_PATH="/etc/letsencrypt/live/$DOMAIN"
    
    msg_info "A configurar Nginx para HTTPS (Porta 443) e Redirecionamento"

    cat <<EOF >/etc/nginx/sites-available/semaphore
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
        proxy_pass http://127.0.0.1:${SEM_PORT};
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
    run_quietly "rm -f /etc/nginx/sites-enabled/semaphore" ""
    run_quietly "ln -sf /etc/nginx/sites-available/semaphore /etc/nginx/sites-enabled/semaphore" "Falha ao ativar o site Semaphore."
    
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
    
    for arg in "$@"; do
        case "$arg" in
            -v|--verbose)
                QUIET_MODE=false
                msg_info "Modo VERBOSO ativado."
                ;;
            -r|--remove)
                REMOVE_MODE=true
                ;;
            -h|--help)
                # show_help # Função de ajuda omitida
                exit 0
                ;;
            *)
                args+=("$arg")
                ;;
        esac 
    done

    if $REMOVE_MODE; then
        remove_semaphore_components
        exit 0
    fi

    CLI_DOMAIN="${args[0]:-}"
    CLI_EMAIL="${args[1]:-}"
    CLI_CF_TOKEN="${args[2]:-}"
    CLI_ENV="${args[3]:-}"
    
    # 1. Instalar/Atualizar Semaphore e Dependências (com novo utilizador)
    setup_semaphore

    # 2. Configurar HTTPS (ou apenas HTTP)
    setup_https "$CLI_DOMAIN" "$CLI_EMAIL" "$CLI_CF_TOKEN" "$CLI_ENV"
    
    msg_info "A limpar o sistema"
    run_quietly "DEBIAN_FRONTEND=noninteractive apt-get -y autoremove" "Falha durante a remoção automática de pacotes."
    run_quietly "DEBIAN_FRONTEND=noninteractive apt-get -y autoclean" "Falha durante a limpeza automática do cache apt."
    
    echo ""
    echo -e "${GN}====================================================================${CL}"
    msg_ok "INSTALAÇÃO DO SEMAPHORE CONCLUÍDA COM SUCESSO!"
    
    if [[ -n "$CLI_DOMAIN" ]]; then
        echo -e "A aplicação deve estar acessível via HTTPS em: ${YW}https://${CLI_DOMAIN}${CL}"
    else
        echo -e "A aplicação deve estar acessível via HTTP em: ${YW}http://<IP_DO_LXC>:${SEM_PORT}${CL} (ou ${YW}http://<IP_DO_LXC>${CL} se Nginx for a única app a correr na porta 80)."
    fi

    echo -e "O serviço está a correr de forma segura com o utilizador: ${YW}${SEM_USER}${CL}"
    echo -e "Credenciais Admin: Verifique o ficheiro ${YW}~/semaphore_admin_password.txt${CL} para a password inicial (se for a primeira instalação)."
    echo -e "${GN}====================================================================${CL}"
}

# INÍCIO
main "$@"
