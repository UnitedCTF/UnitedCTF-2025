FROM archlinux:latest

ARG PASSPHRASE

ENV PASSPHRASE=${PASSPHRASE:?}

RUN pacman -Sy --noconfirm mkinitcpio linux git base-devel

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

RUN uv python install

RUN sed -i 's/^HOOKS.*block/\0 encrypt/' /etc/mkinitcpio.conf
RUN sed -i "s/add_binary 'cryptsetup'/\0\n    add_binary '\/usr\/local\/bin\/auto_decrypt'/" /usr/lib/initcpio/install/encrypt

COPY encrypt /usr/lib/initcpio/hooks/encrypt

COPY passphrase_program/ /tmp/

WORKDIR /tmp

RUN bash -c "sed -E -i 's/(#define PASSPHRASE_SIZE) [0-9]+/\1 ${#PASSPHRASE}/' auto_decrypt.c"
RUN bash -c "sed -i 's/data = .*/data = \"$PASSPHRASE\"/' script.py"

RUN make && uv run script.py && strip auto_decrypt && cp auto_decrypt /usr/local/bin/auto_decrypt

RUN mkinitcpio -p linux

