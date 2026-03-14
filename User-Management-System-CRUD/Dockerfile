# 1. Use Alpine Linux (Very small, removes unnecessary hacker tools)
FROM node:18-alpine

# 2. Create an app directory inside the container
WORKDIR /usr/src/app

# 3. Copy package files and install ONLY production dependencies
COPY package*.json ./
RUN npm install --omit=dev

# 4. Copy your actual application code
COPY . .

# 5. SECURITY FIX: Change ownership of the files to the 'node' user
RUN chown -R node:node /usr/src/app

# 6. SECURITY FIX: Force the container to run as a non-root user
USER node

# 7. Expose your port
EXPOSE 3000

# 8. Start the server
CMD ["node", "server.js"]

