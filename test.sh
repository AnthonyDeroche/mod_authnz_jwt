#docker build -t httpd_tests .
docker run --rm -d -p 127.0.0.1:80:80 --name httpd_tests httpd_tests
python3 -m unittest discover tests -v -f
docker stop httpd_tests
