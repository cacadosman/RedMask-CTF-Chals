FROM node:12

# Create app directory
WORKDIR /app

# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY ./app /app

RUN npm install
# If you are building your code for production
# RUN npm ci --only=production

RUN addgroup -g 82 -S www-data \
&& adduser -u 82 -D -S -G www-data www-data

USER www-data

EXPOSE 3000
CMD [ "node", "index.js" ]
