```bash
# Start the dev CTFd instance, setup manually, choose core-travel as the theme
docker compose up --force-recreate --build --remove-orphans

# In parallel, in core-travel, run:
yarn install
yarn run dev

# Hot reloading should work...
```