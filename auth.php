<?php

include "../model/functions/Logger.php";
// Informações de conexão ao AD
$ldapServer = 'ldap://rgcontadores.local';
$ldapPort = 389;
$ldapAdminUser = 'DOMÍNIO\USUARIOADMINISTRADOR';
$ldapAdminPass = 'SENHADOUSUARIO';

// Usuário e senha fornecidos pelo usuário
$userLogin = $_POST['usuario'];
$userPassword = $_POST['senha'];

// Conexão com o servidor LDAP
$ldapConn = ldap_connect($ldapServer, $ldapPort);
ldap_set_option($ldapConn, LDAP_OPT_PROTOCOL_VERSION, 3);

// Autenticação no servidor AD como administrador
if (ldap_bind($ldapConn, $ldapAdminUser, $ldapAdminPass)) {
    // Filtro de busca do usuário
    $userFilter = "(sAMAccountName=" . $userLogin . ")";
    
    // Busca do usuário no AD
    $userSearch = ldap_search($ldapConn, 'OU=USUARIOS,OU=RG,DC=rgcontadores,DC=local', $userFilter);
    $userEntries = ldap_get_entries($ldapConn, $userSearch);
    
    // Verifica se encontrou o usuário
    if ($userEntries['count'] == 1) {
        // Obtém o grupo do usuário
        $userGroup = '';
        
        // Verifica a senha do usuário
        $userDN = $userEntries[0]['dn'];
        if (ldap_bind($ldapConn, $userDN, $userPassword)) {
            // Autenticação bem-sucedida
            
            // Buscar os grupos do usuário
            $groupFilter = "(member=" . $userDN . ")";
            $groupSearch = ldap_search($ldapConn, 'OU=GRUPOS,OU=RG,DC=rgcontadores,DC=local', $groupFilter);
            $groupEntries = ldap_get_entries($ldapConn, $groupSearch);
            $userEmail = $userEntries[0]['mail'][0];
            // Verificar se o usuário pertence a um grupo específico
            $allowedGroups = array('TI', 'Paralegal', 'administrativo');
            foreach ($groupEntries as $groupEntry) {
                $groupName = $groupEntry['cn'][0];
                if (in_array($groupName, $allowedGroups)) {
                    $userGroup = $groupName;
                    break;
                }
            }
            
            // Verifica se o usuário pertence a um grupo válido
            if (!empty($userGroup)) {
                // Armazena os dados do usuário em variáveis de sessão
                $_SESSION['autenticado'] = true;
                $_SESSION['usuario'] = $userLogin;
                $_SESSION['grupo'] = $userGroup;
                $_SESSION['email'] = $userEmail;
                // LOG DO ACESSO
                Logger("LOGIN - $_SESSION[usuario] Tentando concectar-se");
                //Redireciona a página para o index dos módulos.
                header('location: ../../modulos/');
                exit();
            } else {
                // Usuário não pertence a nenhum grupo válido
                clearstatcache();
                echo "<script>alert('Usuário ou Senha inválida! Cuidado para não bloquear o seu usuário.'); window.location = '../../';</script>";
                exit();
            }
        } else {
            // Senha inválida
            clearstatcache();
           echo "<script>alert('Usuário ou Senha inválida! Cuidado para não bloquear o seu usuário.'); window.location = '../../';</script>";
            exit();
        }
    } else {
        // Usuário não encontrado
        clearstatcache();
        echo "<script>alert('Usuário ou Senha inválida! Cuidado para não bloquear o seu usuário.'); window.location = '../../';</script>";
        exit();
    }
} else {
    // Falha na autenticação do administrador
    clearstatcache();
    echo "<script>alert('FALHA DA AUTENTICAÇÃO GERAL'); window.location = '../../';</script>";
    exit();
}

// Fechar conexão LDAP
ldap_close($ldapConn);
?>
