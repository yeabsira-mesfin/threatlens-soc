import {defineConfig,devices} from '@playwright/test';
export default defineConfig({
 testDir:'./qa',workers:1,retries:process.env.CI?1:0,reporter:[['list'],['html',{open:'never'}]],
 use:{baseURL:'http://127.0.0.1:5173',...devices['Desktop Chrome'],trace:'retain-on-failure',screenshot:'only-on-failure'},
 webServer:[
  {command:'npm run dev -- --host 127.0.0.1 --port 5173',url:'http://127.0.0.1:5173',timeout:45000,reuseExistingServer:!process.env.CI},
  {command:'cd ../backend && python -m uvicorn main:app --host 127.0.0.1 --port 8000',url:'http://127.0.0.1:8000/api/health',timeout:45000,reuseExistingServer:!process.env.CI}
 ]
});
