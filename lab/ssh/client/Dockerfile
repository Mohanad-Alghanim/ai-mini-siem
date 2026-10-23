FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client coreutils \
    && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
ARG LAB_UID=1000
ARG LAB_GID=1000
RUN if ! getent group "$LAB_GID" >/dev/null; then groupadd -g "$LAB_GID" labclient; fi \
    && if ! getent passwd "$LAB_UID" >/dev/null; then useradd -m -u "$LAB_UID" -g "$LAB_GID" -s /bin/sh labclient; fi
ENV HOME=/tmp
