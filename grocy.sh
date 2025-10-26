#!/usr/bin/env bash
#
# Script de Instalação/Upgrade Grocy Standalone com HTTPS Let's Encrypt (PHP 8.2)
# Autor: Adaptado com base nos ficheiros fornecidos.
# Objetivo: Instalar OU atualizar Grocy + Configurar HTTPS (Certbot + Cloudflare DNS)
# Usando PHP 8.2 oficial do Debian 12.
#
# USO: Guarde este ficheiro como 'grocy_installer.sh' no seu LXC Debian 12 e execute-o como root.
# Modo Interativo:
# chmod +x grocy_installer.sh && ./grocy_installer.sh
#
# Modo Automatizado (HTTPS):
# chmod +x grocy_installer.sh && ./grocy_installer.sh <DOMÍNIO> <EMAIL> <CF_TOKEN> [production|staging] [-v|--verbose]
#
# Modo Remoção:
# chmod +x grocy_installer.sh && ./grocy_installer.sh --remove

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

# Variável de controlo de modo silencioso (true por padrão)
QUIET_MODE=true
SPINNER_PID=""

# ------------------------------------------------------------------------------
# Funções do Spinner (Indicador de progresso em background)
# ------------------------------------------------------------------------------

# Inicia o indicador de progresso (spinner) em background
start_spinner() {
    # Executa em subshell
    (
        local i=1
        local spin='-\|/'
        local delay=0.1
        
        while :
        do
            local index=$((i % 4))
            # Usa \r para regressar ao início da linha, %s para o símbolo
            printf "\r${INFO} A executar comando... %s" "${spin:index:1}"
            sleep $delay
            i=$((i + 1))
        done
    ) &
    SPINNER_PID=$!
    # Colocar o processo em background
    disown
}

# Para o indicador de progresso
stop_spinner() {
    if [ -n "$SPINNER_PID" ]; then
        # Enviar um sinal SIGTERM para o processo do spinner
        kill "$SPINNER_PID" 2>/dev/null
        
        # Esperar que o processo termine
        wait "$SPINNER_PID" 2>/dev/null
        
        # Limpa completamente a linha onde o spinner estava (\r volta ao início, \e[K limpa até ao fim da linha)
        printf "\r\e[K"
        SPINNER_PID=""
    fi
}

# Função para executar comandos com controlo de output (silencioso por padrão)
# Usa 'eval' para garantir que os comandos complexos ou com variáveis internas são executados corretamente.
run_quietly() {
    local cmd="$1"
    local error_msg="$2"
    local exit_code=0
    
    if $QUIET_MODE; then
        start_spinner # Inicia o spinner
        
        # Executa o comando com redirecionamento para silenciar output
        eval "$cmd" >/dev/null 2>&1
        exit_code=$?
        
        stop_spinner # Para o spinner
        
        if [ $exit_code -ne 0 ]; then
            fatal "$error_msg"
        fi
    else
        # Executa o comando normalmente
        eval "$cmd" || fatal "$error_msg"
    fi
}


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
    
    # Parar o spinner se estiver a correr, antes de mostrar o erro
    stop_spinner
    
    if [ "$exit_code" -ne 0 ]; then
        msg_error "Falha na Linha $line_number: Comando '$command' terminou com código $exit_code"
    fi
    exit "$exit_code"
}

show_help() {
    echo -e "${GN}====================================================================${CL}"
    echo -e "${YW}         Grocy Standalone Installer/Upgrader (PHP 8.2)        ${CL}"
    echo -e "${GN}====================================================================${CL}"
    echo " "
    echo -e "${YW}USO:${CL}"
    echo "  Execute o script com permissões de root:"
    echo "  ./grocy_installer.sh [OPÇÕES_DE_AUTOMAÇÃO] [OPÇÕES_DE_DEBUG]"
    echo " "
    echo -e "${YW}MODOS DE EXECUÇÃO:${CL}"
    echo -e "  1. ${GN}Modo Interativo (Padrão):${CL}"
    echo "     O script perguntará pelo domínio, e-mail e token Cloudflare."
    echo "     ${GN}./grocy_installer.sh${CL}"
    echo " "
    echo -e "  2. ${GN}Modo Automatizado (CLI):${CL}"
    echo "     Passa todos os parâmetros necessários diretamente na linha de comando."
    echo "     ${GN}./grocy_installer.sh${CL} <DOMÍNIO> <EMAIL> <CF_TOKEN> [production|staging]"
    echo " "
    echo -e "  3. ${GN}Modo Remoção (Uninstall):${CL}"
    echo "     Remove o Grocy, configurações Apache, Certbot e certificados."
    echo "     ${GN}./grocy_installer.sh -r${CL} (ou ${GN}--remove${CL})"
    echo " "
    echo -e "${YW}OPÇÕES DE DEBUG/OUTPUT:${CL}"
    echo "  -v, --verbose     : Ativa o modo verboso. Mostra o output completo das instalações de pacotes (apt, pip)."
    echo "  -r, --remove      : Remove o Grocy, configurações e Certbot."
    echo "  -h, --help        : Mostra esta ajuda e sai."
    echo " "
    echo -e "${YW}EXEMPLOS:${CL}"
    echo "  Instalação/Upgrade em modo automático (produção):"
    echo "  ./grocy_installer.sh grocy.exemplo.pt meu@email.com abcd12345 production"
    echo " "
    echo "  Remover o Grocy completamente:"
    echo "  ./grocy_installer.sh --remove"
    echo -e "${GN}====================================================================${CL}"
    exit 0
}

# ==============================================================================
# 2. FUNÇÕES DE INSTALAÇÃO/UPGRADE (PHP 8.2)
# ==============================================================================

setup_php_debian() {
    local PHP_VERSION="8.2" 
    
    msg_info "A atualizar o SO e a instalar/atualizar utilidades básicas"
    # Uso da nova função run_quietly para evitar erro de redirecionamento (fix #1)
    run_quietly "DEBIAN_FRONTEND=noninteractive apt-get update" "Falha ao atualizar o apt."
    
    msg_info "A instalar dependências básicas (curl, python3-pip, python3-venv, cron)"
    run_quietly "DEBIAN_FRONTEND=noninteractive apt-get install -y curl apt-transport-https unzip python3 python3-pip python3-venv cron" "Falha ao instalar dependências básicas."

    # Executamos o upgrade do sistema
    run_quietly "DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade" "Falha ao fazer upgrade do sistema."
    msg_ok "Sistema e utilidades atualizadas"

    # Instalar ou atualizar Apache e Módulos PHP para Grocy
    msg_info "A instalar/atualizar Apache e módulos PHP ${PHP_VERSION}"
    run_quietly "DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 libapache2-mod-php${PHP_VERSION} php${PHP_VERSION}-cli php${PHP_VERSION}-sqlite3 php${PHP_VERSION}-bz2 php${PHP_VERSION}-bcmath php${PHP_VERSION}-curl php${PHP_VERSION}-gd php${PHP_VERSION}-intl php${PHP_VERSION}-mbstring php${PHP_VERSION}-opcache php${PHP_VERSION}-readline php${PHP_VERSION}-xml php${PHP_VERSION}-zip" "Falha ao instalar pacotes PHP/Apache."
    
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
    # Esta linha deve ser sempre silenciosa (s) mas mostra erros (S)
    curl -fsSL "https://releases.grocy.info/latest" -o grocy_latest.zip || fatal "Falha ao descarregar o Grocy"
    
    msg_info "A extrair os ficheiros"
    # Uso de run_quietly para extração silenciosa
    # Aqui o spinner só aparecerá no modo silencioso
    run_quietly "unzip -o grocy_latest.zip" "Falha ao extrair o ficheiro Grocy"
    rm grocy_latest.zip
    msg_ok "Grocy descarregado e extraído para $DEST_PATH"

    # Copiar ficheiro de configuração APENAS se não existir
    if ! $IS_INSTALLED; then
        msg_info "A copiar ficheiro de configuração inicial"
        cp /var/www/html/config-dist.php /var/www/html/data/config.php
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
        # Usa run_quietly
        run_quietly "DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv" "Falha ao instalar o pacote python3-venv."

        python3 -m venv /opt/certbot-cf-venv || fatal "Falha crítica e persistente ao criar o ambiente virtual Python."
        msg_ok "Ambiente virtual Python criado com sucesso na segunda tentativa."
    fi
    
    source /opt/certbot-cf-venv/bin/activate
    
    # Instalar Certbot e o plugin Cloudflare no venv
    if $QUIET_MODE; then
        start_spinner
        pip install certbot certbot-dns-cloudflare >/dev/null 2>&1
        local pip_exit_code=$?
        stop_spinner
    else
        pip install certbot certbot-dns-cloudflare
        local pip_exit_code=$?
    fi
    
    if [ $pip_exit_code -ne 0 ]; then
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

    # --- NOVO PASSO: Forçar a eliminação do certificado staging (se existir) ---
    if [ -d "/etc/letsencrypt/live/$DOMAIN" ]; then
        msg_info "Certificado existente detetado. A tentar eliminar o certificado antigo ($DOMAIN) para garantir a emissão de Produção."
        # Use o binário do venv
        local delete_cmd="/opt/certbot-cf-venv/bin/certbot delete --cert-name \"$DOMAIN\" --non-interactive"
        
        # Executa silenciosamente, com sucesso mesmo que o certificado não exista ou falhe (o objetivo é limpar)
        if $QUIET_MODE; then
             start_spinner
             eval "$delete_cmd" >/dev/null 2>&1 || true
             stop_spinner
        else
            eval "$delete_cmd" || true
        fi
        msg_ok "Tentativa de eliminação do certificado antigo concluída."
    fi

    # --- Emitir Certificado ---
    msg_info "A emitir certificado Let's Encrypt para $DOMAIN (Ambiente: ${LE_ENV})..."
    
    # O comando certbot é longo, é ideal para o spinner.
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

    # Usamos run_quietly para cobrir a execução do Certbot com o spinner
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
        deactivate
        configure_apache_http 
        return
    fi
    
    msg_ok "Certificado Let's Encrypt emitido com sucesso!"
    deactivate

    # --- Configurar Apache para HTTPS ---
    # Chamamos esta função para atualizar os ficheiros de configuração do Apache
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
    run_quietly "a2enmod ssl headers rewrite" "Falha ao ativar módulos Apache (ssl, headers, rewrite)."

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
    run_quietly "a2dissite 000-default.conf" "Falha ao desativar site padrão do Apache."
    run_quietly "a2ensite grocy.conf" "Falha ao ativar site Grocy HTTP."
    systemctl reload apache2 || systemctl restart apache2
    msg_ok "Apache configurado para HTTP na porta 80."
}

configure_apache_https() {
    local DOMAIN="$1"
    
    msg_info "A configurar VirtualHost HTTPS (Porta 443) e Redirecionamento"

    # Ativar módulos necessários
    run_quietly "a2enmod ssl headers rewrite" "Falha ao ativar módulos Apache (ssl, headers, rewrite)."
    
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
    run_quietly "a2dissite 000-default.conf" "Falha ao desativar site padrão do Apache."
    run_quietly "a2ensite grocy.conf" "Falha ao ativar site Grocy HTTP (Redirecionamento)."   # HTTP Redirect
    run_quietly "a2ensite grocy-ssl.conf" "Falha ao ativar site Grocy HTTPS." # HTTPS Site
    
    # Usar RESTART para garantir que o certificado é atualizado (mantido da versão anterior)
    systemctl restart apache2 || fatal "Falha crítica ao reiniciar o Apache2. Verifique o log."
    msg_ok "Apache configurado para HTTPS (Porta 443) e REINICIADO."
}

# ==============================================================================
# 5. FUNÇÃO DE REMOÇÃO COMPLETA
# ==============================================================================

remove_grocy_components() {
    msg_info "A iniciar o processo de remoção COMPLETA do Grocy"
    
    # 1. Parar o serviço web
    msg_info "A parar o Apache2"
    systemctl stop apache2
    
    # 2. Desativar sites Apache e reverter para o padrão
    msg_info "A desativar configurações Grocy e a reativar site padrão (000-default.conf)"
    run_quietly "a2dissite grocy.conf 2>/dev/null" "Falha ao desativar grocy.conf (pode não existir)."
    run_quietly "rm -f /etc/apache2/sites-available/grocy.conf" ""
    run_quietly "a2dissite grocy-ssl.conf 2>/dev/null" "Falha ao desativar grocy-ssl.conf (pode não existir)."
    run_quietly "rm -f /etc/apache2/sites-available/grocy-ssl.conf" ""
    run_quietly "a2ensite 000-default.conf 2>/dev/null" "Falha ao reativar site padrão."
    
    # 3. Remover ficheiros Grocy
    if [ -d "/var/www/html" ]; then
        msg_info "A remover diretório Grocy (/var/www/html) e os seus ficheiros"
        # Mantemos /var/www/html, mas removemos o conteúdo específico do Grocy
        run_quietly "rm -rf /var/www/html/*" "Falha ao remover o conteúdo do diretório Grocy."
        msg_ok "Ficheiros Grocy removidos."
    else
        msg_info "Diretório Grocy não encontrado. A ignorar remoção de ficheiros da aplicação."
    fi

    # 4. Remover Certbot/Cloudflare
    if [ -d "/opt/certbot-cf-venv" ]; then
        msg_info "A remover ambiente virtual Certbot (/opt/certbot-cf-venv)"
        run_quietly "rm -rf /opt/certbot-cf-venv" "Falha ao remover Certbot VENV."
        msg_ok "Certbot VENV removido."
    fi
    
    # Remover segredos do Cloudflare
    if [ -f "/root/.secrets/cloudflare_credentials.ini" ]; then
        msg_info "A remover credenciais Cloudflare"
        run_quietly "rm -f /root/.secrets/cloudflare_credentials.ini" "Falha ao remover credenciais Cloudflare."
        run_quietly "rmdir /root/.secrets 2>/dev/null" "" # Tenta remover o diretório se estiver vazio
        msg_ok "Credenciais Cloudflare removidas."
    fi

    # Remover certificados Let's Encrypt
    msg_info "A tentar remover certificados Let's Encrypt para Grocy"
    local certbot_bin="/opt/certbot-cf-venv/bin/certbot"
    
    # Tenta usar o binário dentro do venv ou o binário do sistema
    if [ ! -f "$certbot_bin" ]; then
        certbot_bin=$(command -v certbot 2>/dev/null || echo "")
    fi

    if [ -n "$certbot_bin" ]; then
        # Lista e filtra os nomes de certificados (heurístico)
        local domains_to_remove
        domains_to_remove=$("$certbot_bin" certificates 2>/dev/null | grep 'Certificate Name' | awk '{print $3}' | grep -i 'grocy\|grocy.' || true)
        
        if [ -n "$domains_to_remove" ]; then
            for d in $domains_to_remove; do
                msg_info "A eliminar o certificado Let's Encrypt para $d"
                # Forçamos a eliminação
                run_quietly "\"$certbot_bin\" delete --cert-name \"$d\" --non-interactive >/dev/null 2>&1" "Falha ao eliminar certificado $d. Remova-o manualmente se necessário."
            done
            msg_ok "Eliminação de certificados Grocy concluída."
        else
            msg_info "Nenhum certificado Grocy detetado para eliminação."
        fi
        
        # Limpa o cron job do Certbot (se o binário existir)
        msg_info "A remover a entrada de renovação do Certbot no crontab"
        (crontab -l 2>/dev/null | grep -v 'certbot renew') | crontab - 2>/dev/null
        msg_ok "Entrada cron removida."
    else
        msg_info "Certbot não instalado, a ignorar remoção de certificados."
    fi
    
    # 5. Reiniciar/Recarregar Apache
    msg_info "A recarregar a configuração do Apache"
    systemctl reload apache2 || systemctl start apache2
    msg_ok "Apache recarregado e a servir o site padrão (HTTP)."
    
    # 6. Remover Dependências (Opcional/Manual)
    echo ""
    echo -e "${GN}====================================================================${CL}"
    msg_ok "REMOÇÃO DE COMPONENTES GROCY CONCLUÍDA."
    echo ""
    msg_info "PASSOS FINAIS: Remoção de Pacotes do Sistema (Requer Confirmação)"
    echo "Os seguintes pacotes foram instalados para o Grocy. Se não forem usados por outras"
    echo "aplicações, deve removê-los para uma limpeza completa:"
    echo ""
    echo -e "Pacotes a considerar remover:"
    echo -e "${YW}  - PHP 8.2 e Módulos:${CL} libapache2-mod-php8.2 php8.2-cli php8.2-sqlite3 php8.2-bz2 php8.2-bcmath php8.2-curl php8.2-gd php8.2-intl php8.2-mbstring php8.2-opcache php8.2-readline php8.2-xml php8.2-zip"
    echo -e "${YW}  - Servidor Web:${CL} apache2"
    echo ""
    echo -e "${GN}SUGESTÃO DE COMANDO PARA REMOÇÃO COMPLETA DOS PACOTES PHP 8.2:${CL}"
    echo -e "  ${YW}apt-get purge --autoremove libapache2-mod-php8.2 php8.2-cli php8.2-*{CL}"
    echo ""
    echo -e "Se tiver a certeza que não usa o Apache para mais nada:"
    echo -e "  ${YW}apt-get purge --autoremove apache2${CL}"
    echo -e "${GN}====================================================================${CL}"
    
    exit 0
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
    
    # ----------------------------------------------------
    # Processar Flags e Argumentos
    # ----------------------------------------------------
    for arg in "$@"; do
        case "$arg" in
            -v|--verbose)
                QUIET_MODE=false # Define globalmente, permitindo output
                msg_info "Modo VERBOSO ativado. O output dos comandos de instalação será visível."
                ;;
            -r|--remove)
                REMOVE_MODE=true # Ativa o modo de remoção
                ;;
            -h|--help)
                show_help # Exibir ajuda e sair
                ;;
            *)
                args+=("$arg") # Coleta argumentos não-flag
                ;;
        esac # <--- CORREÇÃO: Usar esac para fechar o bloco case
    done

    # Se o modo de remoção estiver ativo, executa a função e sai
    if $REMOVE_MODE; then
        remove_grocy_components
    fi

    # Atribui argumentos não-flag aos parâmetros CLI (Apenas para instalação)
    CLI_DOMAIN="${args[0]:-}"
    CLI_EMAIL="${args[1]:-}"
    CLI_CF_TOKEN="${args[2]:-}"
    CLI_ENV="${args[3]:-}"
    
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
    run_quietly "DEBIAN_FRONTEND=noninteractive apt-get -y autoremove" "Falha durante a remoção automática de pacotes."
    run_quietly "DEBIAN_FRONTEND=noninteractive apt-get -y autoclean" "Falha durante a limpeza automática do cache apt."
    msg_ok "Processo Grocy finalizado com sucesso. Verifique o acesso via HTTP/HTTPS."
}

# INÍCIO
main "$@"
