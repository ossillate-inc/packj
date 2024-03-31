# syntax=docker/dockerfile:1

FROM ubuntu:22.04

# Set up local user
RUN groupadd -g 1001 ubuntu && \
    useradd -rm -d /home/ubuntu -s /bin/bash -g ubuntu -u 1001 ubuntu

# Enable the apt downloaded packages cache, so we can hook it up to a Docker
# BuildKit cache to speed up subsequent image builds.
RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

# Add upstream Node.js apt repository
ADD --chmod=755 https://deb.nodesource.com/setup_16.x /tmp/setup_16.x

# Install OS (apt) dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    /tmp/setup_16.x && \
    apt-get install --quiet --yes python3 gcc python3-dev python3-pip ruby-full rubygems-integration musl-dev protobuf-compiler git ruby-full libmagic-dev strace curl autoconf build-essential libfreetype-dev libssl-dev gawk nodejs

# Install Ruby dependencies
RUN --mount=type=cache,target=/root/.gem,sharing=locked \
    gem install parser:3.0.0.0 google-protobuf:3.21.2 rubocop:1.31.1

# Install pip dependencies
COPY requirements.txt requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip,sharing=locked \
    pip3 install --upgrade --progress-bar off --disable-pip-version-check -r requirements.txt

# Set up Packj sandbox tool
COPY ./packj/sandbox /tmp/sandbox-install
RUN cd /tmp/sandbox-install && \
    ./install.sh -v && \
    mv /tmp/sandbox-install/libsbox.so /tmp && \
    rm -rf /tmp/sandbox-install

WORKDIR /home/ubuntu/packj

COPY --chown=ubuntu:ubuntu . .
RUN mv /tmp/libsbox.so /home/ubuntu/packj/packj/sandbox/libsbox.so

RUN cd /home/ubuntu && \
    mkdir .local ruby .npm .npm/_cacache && \
    chown -R ubuntu:ubuntu /home/ubuntu

USER ubuntu
ENTRYPOINT ["python3", "main.py"]
