#!/usr/bin/env bash
#
# Script de Instalação/Upgrade Grocy Standalone com HTTPS Let's Encrypt (PHP 8.2)
# Autor: Adaptado com base nos ficheiros fornecidos.
# Objetivo: Instalar OU atualizar Grocy + Configurar HTTPS (Certbot + Cloudflare DNS)
#           Usando PHP 8.2 oficial do Debian 12.
#
# USO: Guarde este ficheiro como 'install_grocy.sh' no seu LXC Debian 12 e execute-o como root.
#      Modo Interativo:
#      chmod +x install_grocy.sh && ./install_or_upgrade_grocy_https_cf_82.sh
#
#      Modo Automatizado (HTTPS):
#      chmod +x install_grocy.sh && ./install_or_upgrade_grocy_https_cf_82.sh <DOMÍNIO> <EMAIL> <CF_TOKEN> [production|staging]

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

# Configurar gestão de erros
catch_errors() {
    set -Eeuo pipefail
    trap 'error_handler $LINENO "$BASH_COMMAND"' ERR
    return 0 # Adicionado para garantir que a função catch_errors não falha imediatamente
}

error_handler() {
    local exit_code="$?"
    local line_number="$1"
    local command="$2"
    if [ "$exit_code" -ne 0 ]; then
        msg_error "Falha na Linha $line_number: Comando '$command' terminou com código $exit_code"
    fi
    exit "$exit_code"
}

# ==============================================================================
# 2. FUNÇÕES DE INSTALAÇÃO/UPGRADE (PHP 8.2)
# ==============================================================================

setup_php_debian() {
    local PHP_VERSION="8.2" 
    
    msg_info "A atualizar o SO e a instalar/atualizar utilidades básicas"
    DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1 || fatal "Falha ao atualizar o apt."
    
    # Instalar explicitamente todas as dependências venv por segurança
    # Removida a redundância 'python3.11-venv', mantendo apenas o metapacote 'python3-venv'.
    msg_info "A instalar dependências básicas (curl, python3-pip, python3-venv, cron)"
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl apt-transport-https unzip python3 python3-pip python3-venv cron >/dev/null 2>&1

    # Executamos o upgrade do sistema
    DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade >/dev/null 2>&1
    msg_ok "Sistema e utilidades atualizadas"

    # Instalar ou atualizar Apache e Módulos PHP para Grocy
    msg_info "A instalar/atualizar Apache e módulos PHP ${PHP_VERSION}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 libapache2-mod-php${PHP_VERSION} \
                                   php${PHP_VERSION}-cli php${PHP_VERSION}-sqlite3 php${PHP_VERSION}-bz2 \
                                   php${PHP_VERSION}-bcmath php${PHP_VERSION}-curl php${PHP_VERSION}-gd \
                                   php${PHP_VERSION}-intl php${PHP_VERSION}-mbstring php${PHP_VERSION}-opcache \
                                   php${PHP_VERSION}-readline php${PHP_VERSION}-xml php${PHP_VERSION}-zip >/dev/null 2>&1
    
    msg_ok "Apache e PHP ${PHP_VERSION} garantidos"
}

fetch_and_deploy_grocy() {
    local DEST_PATH="/var/www/html"
    local CONFIG_FILE="${DEST_PATH}/data/config.php"
    local IS_INSTALLED=false

    if [ -d "$DEST_PATH/public" ]; then IS_INSTALLED=true; fi

    msg_info "A preparando o diretório de destino"
    mkdir -p "$DEST_PATH"
    cd "$DEST_PATH" || fatal "Não foi possível mudar para o diretório $DEST_PATH"
    
    if $IS_INSTALLED; then
        msg_info "Instalação Grocy existente detetada. A fazer upgrade..."
    else
        msg_info "Instalação Grocy não detetada. A instalar pela primeira vez..."
    fi

    msg_info "A descarregar a última versão do Grocy"
    curl -fsSL "https://releases.grocy.info/latest" -o grocy_latest.zip || fatal "Falha ao descarregar o Grocy"
    
    msg_info "A extrair os ficheiros"
    unzip -o grocy_latest.zip >/dev/null 2>&1 || fatal "Falha ao extrair o ficheiro Grocy"
    rm grocy_latest.zip
    msg_ok "Grocy descarregado e extraído para $DEST_PATH"

    # Copiar ficheiro de configuração APENAS se não existir
    if ! $IS_INSTALLED; then
        msg_info "A copiar ficheiro de configuração inicial"
        cp /var/www/html/config-dist.php "$CONFIG_FILE"
        msg_ok "Ficheiro de configuração inicial criado em $CONFIG_FILE"
    else
        msg_ok "Ficheiro de configuração existente mantido."
    fi
}

configure_permissions() {
    msg_info "A configurar permissões"
    chown -R www-data:www-data /var/www/html
    chmod +x /var/www/html/update.sh
    msg_ok "Permissões configuradas."
}

# ==============================================================================
# 3. CONFIGURAÇÃO HTTPS (Certbot/Cloudflare)
# ==============================================================================

setup_https() {
    local CLI_DOMAIN="$1"
    local CLI_EMAIL="$2"
    local CLI_CF_TOKEN="$3"
    local CLI_ENV="${4:-production}" # O 4º argumento define o ambiente (padrão: production)

    local DOMAIN
    local EMAIL
    local CF_TOKEN
    local LE_ENV
    local LE_SERVER_ARG="" # Argumento Let's Encrypt (vazio para produção)
    local USE_HTTPS="n"
    local DEST_PATH="/var/www/html"
    
    # Verifica se os parâmetros foram passados via CLI
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
        # Modo Interativo
        echo ""
        read -r -p "Deseja configurar HTTPS com Let's Encrypt (Cloudflare DNS)? [y/N]: " USE_HTTPS
        USE_HTTPS=$(echo "$USE_HTTPS" | tr '[:upper:]' '[:lower:]')

        if [[ "$USE_HTTPS" != "y" ]]; then
            msg_info "A configurar apenas HTTP. Pode configurar HTTPS mais tarde."
            configure_apache_http
            return
        fi
        
        # --- Coletar Informação do Utilizador ---
        msg_info "--- Configuração HTTPS (Let's Encrypt / Cloudflare) ---"
        read -r -p "Introduza o seu domínio (ex: grocy.o-seu-dominio.pt): " DOMAIN
        read -r -p "Introduza o seu e-mail (para avisos de renovação): " EMAIL
        echo ""
        read -r -p "Introduza o seu API Token da Cloudflare (com permissão DNS-Edit): " CF_TOKEN
        echo ""
        
        # --- Escolha do Ambiente Let's Encrypt ---
        read -r -p "Deseja usar o ambiente de TESTE (Staging) do Let's Encrypt? [y/N]: " USE_STAGING
        USE_STAGING=$(echo "$USE_STAGING" | tr '[:upper:]' '[:lower:]')

        if [[ "$USE_STAGING" == "y" ]]; then
            LE_SERVER_ARG="--staging"
            LE_ENV="staging"
            msg_info "AVISO: Usar Staging é útil para testes. O certificado NÃO será válido publicamente."
        else
            LE_ENV="production"
            msg_info "A usar ambiente de PRODUÇÃO (Certificado válido)."
        fi
    fi
    
    if [[ "$USE_HTTPS" != "y" ]]; then
        configure_apache_http
        return
    fi
    
    if [[ -z "$DOMAIN" || -z "$EMAIL" || -z "$CF_TOKEN" ]]; then
        fatal "Domínio, E-mail ou Cloudflare Token não podem estar vazios."
    fi
    
    # --- Instalar Certbot e Plugin Cloudflare ---
    msg_info "A instalar Certbot e Plugin Cloudflare"
    
    # Lógica de resiliência "Try-Catch" para a criação do VENV
    if python3 -m venv /opt/certbot-cf-venv; then
        msg_ok "Ambiente virtual Python criado com sucesso."
    else
        msg_info "Primeira tentativa de 'venv' falhou. A garantir a instalação de 'python3-venv' e tentar de novo."
        DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv >/dev/null 2>&1
        python3 -m venv /opt/certbot-cf-venv || fatal "Falha crítica e persistente ao criar o ambiente virtual Python."
        msg_ok "Ambiente virtual Python criado com sucesso na segunda tentativa."
    fi
    
    source /opt/certbot-cf-venv/bin/activate
    # Instalar Certbot e o plugin Cloudflare no venv
    pip install certbot certbot-dns-cloudflare >/dev/null 2>&1
    
    if [ $? -ne 0 ]; then
        msg_error "Falha ao instalar Certbot/Plugin. A reverter para HTTP."
        deactivate
        configure_apache_http
        return
    fi
    msg_ok "Certbot e Plugin Cloudflare instalados"

    # --- Criar ficheiro de credenciais Cloudflare ---
    CF_CRED_FILE="/root/.secrets/cloudflare_credentials.ini"
    mkdir -p /root/.secrets
    
    cat <<EOF >"$CF_CRED_FILE"
dns_cloudflare_api_token = $CF_TOKEN
EOF
    chmod 600 "$CF_CRED_FILE" # Permissões restritas, apenas root pode ler/escrever

    # --- Emitir Certificado ---
    msg_info "A emitir certificado Let's Encrypt para $DOMAIN (Ambiente: ${LE_ENV})..."
    
    # REMOVIDO: Argumento não reconhecido (--overwrite-cert)
    /opt/certbot-cf-venv/bin/certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$CF_CRED_FILE" \
        --email "$EMAIL" \
        --domains "$DOMAIN" \
        --agree-tos \
        --non-interactive \
        --cert-name "$DOMAIN" \
        $LE_SERVER_ARG || {
        msg_error "Falha na emissão do certificado. Verifique as credenciais e o DNS."
        deactivate
        # Configura HTTP em caso de falha de Certbot
        configure_apache_http 
        return
    }
    
    msg_ok "Certificado Let's Encrypt emitido com sucesso!"
    deactivate

    # --- Configurar Apache para HTTPS ---
    configure_apache_https "$DOMAIN"
    
    # --- Configurar Renovação Automática (Cron) ---
    msg_info "A configurar renovação automática do certificado"
    
    # Tratar o erro de 'crontab -l' quando não existe crontab, forçando a ser uma string vazia.
    CRON_CONTENT=$(crontab -l 2>/dev/null || echo "")
    
    # Remover entradas antigas de 'certbot renew' e adicionar a nova, passando o resultado para 'crontab -'
    (echo "$CRON_CONTENT" | grep -v 'certbot renew'; echo "0 3 * * * /opt/certbot-cf-venv/bin/certbot renew --quiet") | crontab - || fatal "Falha ao definir o cron job."
    msg_ok "Renovação automática configurada."
}

# ==============================================================================
# 4. CONFIGURAÇÃO APACHE (HTTP/HTTPS)
# ==============================================================================

configure_apache_http() {
    msg_info "A configurar VirtualHost HTTP padrão"
    
    # Instala o módulo SSL por segurança
    a2enmod ssl headers rewrite >/dev/null 2>&1

    # Cria ou atualiza o VirtualHost HTTP (porta 80)
    cat <<EOF >/etc/apache2/sites-available/grocy.conf
<VirtualHost *:80>
  ServerAdmin webmaster@localhost
  DocumentRoot /var/www/html/public
  ErrorLog /var/log/apache2/error.log
<Directory /var/www/html/public>
  Options Indexes FollowSymLinks MultiViews
  AllowOverride All
  Order allow,deny
  allow from all
</Directory>
</VirtualHost>
EOF
    a2dissite 000-default.conf >/dev/null 2>&1
    a2ensite grocy.conf >/dev/null 2>&1
    systemctl reload apache2 || systemctl restart apache2
    msg_ok "Apache configurado para HTTP na porta 80."
}

configure_apache_https() {
    local DOMAIN="$1"
    
    msg_info "A configurar VirtualHost HTTPS (Porta 443) e Redirecionamento"

    # Ativar módulos necessários
    a2enmod ssl headers rewrite >/dev/null 2>&1
    
    # Ficheiros do Certificado
    # O caminho continua a usar o DOMAIN, dependendo do --overwrite-cert
    local CERT_PATH="/etc/letsencrypt/live/$DOMAIN"
    
    # Configurar o VirtualHost HTTP para redirecionar para HTTPS (porta 80)
    cat <<EOF >/etc/apache2/sites-available/grocy.conf
<VirtualHost *:80>
  ServerName $DOMAIN
  Redirect permanent / https://$DOMAIN/
</VirtualHost>
EOF

    # Configurar o VirtualHost HTTPS (porta 443)
    cat <<EOF >/etc/apache2/sites-available/grocy-ssl.conf
<VirtualHost *:443>
  ServerName $DOMAIN
  ServerAdmin webmaster@localhost
  DocumentRoot /var/www/html/public
  ErrorLog /var/log/apache2/error.log
  SSLEngine on
  SSLCertificateFile ${CERT_PATH}/fullchain.pem
  SSLCertificateKeyFile ${CERT_PATH}/privkey.pem
  
<Directory /var/www/html/public>
  Options Indexes FollowSymLinks MultiViews
  AllowOverride All
  Order allow,deny
  allow from all
</Directory>

  # Cabeçalhos de segurança recomendados
  Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set X-XSS-Protection "1; mode=block"
  
</VirtualHost>
EOF

    # Ativar sites e reiniciar Apache
    a2dissite 000-default.conf >/dev/null 2>&1
    a2ensite grocy.conf >/dev/null 2>&1   # HTTP Redirect
    a2ensite grocy-ssl.conf >/dev/null 2>&1 # HTTPS Site
    
    systemctl reload apache2 || systemctl restart apache2
    msg_ok "Apache configurado para HTTPS (Porta 443)."
}

# ==============================================================================
# 5. FLUXO PRINCIPAL
# ==============================================================================

main() {
    catch_errors
    
    local CLI_DOMAIN="${1:-}"
    local CLI_EMAIL="${2:-}"
    local CLI_CF_TOKEN="${3:-}"
    local CLI_ENV="${4:-}"
    
    # 1. Instalar/Atualizar PHP e Dependências do SO
    setup_php_debian

    # 2. Descarregar/Atualizar Grocy
    fetch_and_deploy_grocy
    
    # 3. Configurar Permissões
    configure_permissions
    
    # 4. Configurar HTTPS (ou apenas HTTP, se o utilizador recusar)
    setup_https "$CLI_DOMAIN" "$CLI_EMAIL" "$CLI_CF_TOKEN" "$CLI_ENV"
    
    # 5. Limpeza
    msg_info "A limpar o sistema"
    DEBIAN_FRONTEND=noninteractive apt-get -y autoremove >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get -y autoclean >/dev/null 2>&1
    msg_ok "Processo Grocy finalizado com sucesso. Verifique o acesso via HTTP/HTTPS."
}

# INÍCIO
main "$@"
