import {test,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
test('ThreatLens login and analyst dashboard have no serious WCAG failures',async({page})=>{
 await page.goto('/');
 let result=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21a','wcag21aa']).analyze();
 expect(result.violations.filter(v=>['serious','critical'].includes(v.impact)).map(v=>({id:v.id,impact:v.impact,nodes:v.nodes.map(n=>n.target)}))).toEqual([]);
 await page.locator('input[type=password]').fill(process.env.THREATLENS_DEMO_PASSWORD);
 await page.getByRole('button',{name:/Open analyst workspace/}).click();
 await expect(page.getByRole('heading',{name:'Security operations overview'})).toBeVisible();
 result=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21a','wcag21aa']).analyze();
 expect(result.violations.filter(v=>['serious','critical'].includes(v.impact)).map(v=>({id:v.id,impact:v.impact,nodes:v.nodes.map(n=>n.target)}))).toEqual([]);
});