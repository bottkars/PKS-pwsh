# PKS-pwsh
# PKS-pwsh



 curl 'https://api.pksazure.labbuildr.com:8443/oauth/token' -i -X POST \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d 'client_id=pks_cli&&grant_type=password&username=kbott&password=Breda1208&token_format=opaquelogin_hint=%7B%22origin%22%3A%22uaa%22%7D'