FROM node:18
LABEL maintainer="Scavin <scavin@appinn.com>"

ENV LANG=C.UTF-8
WORKDIR /ws-scrcpy

# 安装系统依赖（此层变化少，长期缓存）
RUN npm install -g node-gyp && \
    apt-get update && apt-get install -y android-tools-adb && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# 单独复制 package.json，仅在依赖变化时才重跑 npm install（缓存友好）
COPY package*.json ./
RUN npm install

# 复制源码并构建（每次改代码只重跑这两步，约 1-2 分钟）
COPY . .
RUN npm run dist

EXPOSE 8000

CMD ["node", "dist/index.js", "--video-codec=h265", "-b", "16M", "-m", "1920", "--max-fps=60"]
