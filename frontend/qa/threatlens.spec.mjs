import {test,expect} from '@playwright/test';

test('analyst workflow: responsive overview, detections, investigations and role denial',async({page,request},testInfo)=>{
  await page.goto('/');
  await expect(page.getByRole('heading',{name:'Sign in to workspace'})).toBeVisible();
  await page.locator('input[type=password]').fill(process.env.THREATLENS_DEMO_PASSWORD);
  await page.getByRole('button',{name:/Open analyst workspace/}).click();
  await expect(page.getByRole('heading',{name:'Security operations overview'})).toBeVisible();
  await expect(page.getByText('Recent detection activity')).toBeVisible();
  await page.screenshot({path:testInfo.outputPath('threatlens-desktop.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  await expect(page.getByRole('navigation',{name:'SOC navigation'})).toBeVisible();
  await page.screenshot({path:testInfo.outputPath('threatlens-mobile.png'),fullPage:true});
  await page.setViewportSize({width:1400,height:900});
  await page.getByRole('button',{name:/Alert queue/}).click();
  await expect(page.getByRole('heading',{name:'Alert queue'})).toBeVisible();
  await expect(page.getByText('AUTH_BRUTE_FORCE').first()).toBeVisible();
  await page.getByRole('button',{name:'Investigate'}).first().click();
  await expect(page.getByText(/Mapped ATT&CK technique/)).toBeVisible();
  await page.getByRole('button',{name:'Save triage'}).click();
  await expect(page.getByText('Triage saved')).toBeVisible();
  await page.getByRole('button',{name:/Investigations/}).click();
  await page.getByPlaceholder('Case title').fill('Synthetic browser QA incident');
  await page.getByRole('button',{name:'Open case'}).click();
  await expect(page.getByText('Investigation created')).toBeVisible();
  await expect(page.getByText('Synthetic browser QA incident')).toBeVisible();
  const viewer=await request.post('http://127.0.0.1:8000/api/auth/login',{data:{username:'viewer',password:process.env.THREATLENS_DEMO_PASSWORD}});
  expect(viewer.status()).toBe(200);
  const token=(await viewer.json()).token;
  const forbidden=await request.post('http://127.0.0.1:8000/api/ingest',{
    headers:{Authorization:'Bearer '+token},data:[{timestamp:'2026-10-28T12:00:00Z',event_type:'web',action:'GET'}]
  });
  expect(forbidden.status()).toBe(403);
});
