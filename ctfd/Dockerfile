FROM node:24-alpine AS builder

WORKDIR /build/core-travel

COPY core-travel/package.json core-travel/yarn.lock ./
RUN yarn install

COPY core-travel /build/core-travel/
RUN yarn run build

FROM ctfd/ctfd:3.8.0

# patch that makes index.html an actual template
RUN sed -i -e 's/page = get_page/if route == "index":\n        return render_template("index.html")\n    page = get_page/g' /opt/CTFd/CTFd/views.py

COPY --from=builder /build/core-travel /opt/CTFd/CTFd/themes/core-travel

COPY ./ansible_challenges /opt/CTFd/CTFd/plugins/ansible_challenges
COPY ./discord_webhook /opt/CTFd/CTFd/plugins/discord_webhook

RUN /opt/venv/bin/pip install --no-cache-dir -r /opt/CTFd/CTFd/plugins/discord_webhook/requirements.txt
