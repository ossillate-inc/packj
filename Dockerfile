FROM ubuntu:22.04

RUN apt update -y --fix-missing
RUN apt install -y --fix-missing python3 gcc python3-dev python3-pip ruby-full rubygems-integration musl-dev protobuf-compiler git ruby-full libmagic-dev strace curl autoconf build-essential libfreetype-dev libssl-dev gawk
RUN gem install parser:3.0.0.0 google-protobuf:3.21.2 rubocop:1.31.1
RUN curl -fsSL https://deb.nodesource.com/setup_16.x | bash - && apt-get install -y nodejs

RUN groupadd -g 1001 ubuntu
RUN useradd -rm -d /home/ubuntu -s /bin/bash -g ubuntu -u 1001 ubuntu

WORKDIR /home/ubuntu/packj

COPY --chown=ubuntu:ubuntu . .
RUN pip3 install -r requirements.txt && cd sandbox && ./install.sh && mkdir /home/ubuntu/.local /home/ubuntu/.ruby /home/ubuntu/.npm /home/ubuntu/.npm/_cacache && chown -R ubuntu:ubuntu /home/ubuntu

USER ubuntu
ENTRYPOINT ["python3", "main.py"]
