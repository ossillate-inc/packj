FROM ubuntu:20.04

WORKDIR /packj

RUN apt update -y
RUN apt install -y python3 gcc python3-dev python3-pip ruby-full rubygems-integration musl-dev protobuf-compiler git ruby-full libmagic-dev
RUN gem install parser:3.0.0.0 google-protobuf:3.21.2 rubocop:1.31.1

COPY . .
RUN pip3 install -r requirements.txt

ENTRYPOINT ["python3", "main.py"]
