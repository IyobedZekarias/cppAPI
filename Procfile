worker: docker build -t crypto .
web: docker run -p 443:443 -e PORT=443 -ti crypto:latest /cppAPI/build/cppAPI