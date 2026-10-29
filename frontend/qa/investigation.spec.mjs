import {test,expect} from '@playwright/test';

test('IOC correlation and analyst case notes',async({page},testInfo)=>{
 await page.goto('/');
 await page.locator('input[type=password]').fill(process.env.THREATLENS_DEMO_PASSWORD);
 await page.getByRole('button',{name:/Open analyst workspace/}).click();
 await page.getByRole('button',{name:/IOC lookup/}).click();
 await expect(page.getByRole('heading',{name:'IOC lookup'})).toBeVisible();
 await page.getByRole('button',{name:'Search telemetry'}).click();
 await expect(page.getByRole('heading',{name:'Matching records (5)'})).toBeVisible();
 await page.evaluate(()=>window.scrollTo(0,0));
 await page.screenshot({path:testInfo.outputPath('threatlens-ioc-search.png'),fullPage:true});
 await page.getByRole('button',{name:/Investigations/}).click();
 await page.getByPlaceholder('Case title').fill('QA Investigation Notes '+Date.now());
 await page.getByRole('button',{name:'Open case'}).click();
 await expect(page.getByText('Investigation created')).toBeVisible();
 await page.getByRole('button',{name:'Edit case'}).first().click();
 await page.getByLabel('Investigation notes').fill('Synthetic analyst investigation with verified IOC search.');
 await page.getByRole('button',{name:'Save investigation'}).click();
 await expect(page.getByText('Case saved')).toBeVisible();
});
