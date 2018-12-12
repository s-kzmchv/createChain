openssl req -newkey rsa:4096 -x509 -nodes -extensions my_ca  -config C:\Users\kuzmichev\Downloads\openssl.cnf -subj /C=RU/L=Saint-Petersburg/O=SUAI/OU=faculty5/CN=SUAI -keyout C:\Users\kuzmichev\Downloads\certs\ca.key  -out C:\Users\kuzmichev\Downloads\certs\ca.crt -days 3654


openssl req -newkey rsa:4096 -nodes -config C:\Users\kuzmichev\Downloads\openssl.cnf -subj /C=RU/L=Saint-Petersburg/O=SUAI/OU=faculty5/CN=SUAI_au14_28 -keyout C:\Users\kuzmichev\Downloads\certs\domain2.key  -out C:\Users\kuzmichev\Downloads\certs\domain2.csr

openssl x509 -req -days 365  -CA C:\Users\kuzmichev\Downloads\certs\ca.crt -CAkey C:\Users\kuzmichev\Downloads\certs\ca.key  -set_serial 01 -extfile C:\Users\kuzmichev\Downloads\openssl.cnf -extensions my_intermediate_ca  -in C:\Users\kuzmichev\Downloads\certs\domain2.csr -out C:\Users\kuzmichev\Downloads\certs\domain2.crt


openssl pkcs12 -export -in C:\Users\kuzmichev\Downloads\certs\domain2.crt -inkey C:\Users\kuzmichev\Downloads\certs\domain2.key -out C:\Users\kuzmichev\Downloads\certs\domain2.p12






openssl req -newkey rsa:4096 -nodes -config C:\Users\kuzmichev\Downloads\openssl.cnf -subj /C=RU/L=Saint-Petersburg/O=SUAI/OU=faculty5/CN=ASUAI_au14_29 -keyout C:\Users\kuzmichev\Downloads\certs\domain3.key  -out C:\Users\kuzmichev\Downloads\certs\domain3.csr

openssl x509 -req -days 365  -CA C:\Users\kuzmichev\Downloads\certs\ca.crt -CAkey C:\Users\kuzmichev\Downloads\certs\ca.key  -set_serial 01 -extfile C:\Users\kuzmichev\Downloads\openssl.cnf -extensions my_intermediate_ca  -in C:\Users\kuzmichev\Downloads\certs\domain3.csr -out C:\Users\kuzmichev\Downloads\certs\domain3.crt


openssl pkcs12 -export -in C:\Users\kuzmichev\Downloads\certs\domain3.crt -inkey C:\Users\kuzmichev\Downloads\certs\domain3.key -out C:\Users\kuzmichev\Downloads\certs\domain3.p12




pause
