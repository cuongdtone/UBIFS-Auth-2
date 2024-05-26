
openssl req \
    -x509 \
    -sha256 \
    -newkey rsa:4096 \
    -keyout pvtkey.pem \
    -days 3650 \
    -subj '/CN=test' \
    -nodes \
    -sigopt rsa_padding_mode:pss \
    -sigopt rsa_mgf1_md:sha256 \
    -sigopt rsa_pss_saltlen:32 \
    -outform der \
    -out cert.pem