import { test, expect } from '@playwright/test';

test('Console login and cluster health monitoring', async ({ page }) => {
  test.setTimeout(120000);
  
  // Navigate to console
  await page.goto('http://localhost:8087/');
  
  // Verify login page loads correctly
  await expect(page.getByRole('heading', { name: 'Log in' })).toBeVisible();
  await expect(page.getByLabel('Username or email')).toBeVisible();
  await expect(page.getByLabel('Password')).toBeVisible();
  
  // Perform login
  await page.getByLabel('Username or email').fill('demo');
  await page.getByLabel('Password').fill('demo');
  await page.getByRole('button', { name: 'Log in' }).click();
  
  // Wait for login to complete and verify successful authentication
  await expect(page).toHaveURL(/.*(?<!\/login)$/); // URL should not end with /login
  
  // Verify we're on the dashboard - just check that we have some content and no login form
  await expect(page.locator('input[type="password"]')).not.toBeVisible();
  
  // Console-specific: Verify main dashboard shows Management components
  await expect(page.locator('h3:has-text("Management components")')).toBeVisible({ timeout: 30000 });
  
  // Verify we can see healthy status indicators (multiple components should be healthy)
  await expect(page.locator('span:has-text("Healthy")').first()).toBeVisible({ timeout: 20000 });
  
  // Navigate to the cluster-specific page to verify automation components
  await page.goto('http://localhost:8087/clusters/camunda-platform');
  
  // Verify automation components section loads
  await expect(page.locator('h3:has-text("Automation components")')).toBeVisible({ timeout: 30000 });
  
  // Verify orchestration automation components are healthy
  await expect(page.locator('h6:has-text("Zeebe")')).toBeVisible({ timeout: 15000 });
  await expect(page.locator('h6:has-text("Tasklist")')).toBeVisible({ timeout: 15000 });
  await expect(page.locator('h6:has-text("Operate")')).toBeVisible({ timeout: 15000 });
  await expect(page.locator('h6:has-text("Optimize")')).toBeVisible({ timeout: 15000 });
  
  // Verify all automation components show healthy status
  const automationHealthyCount = await page.locator('span:has-text("Healthy")').count();
  expect(automationHealthyCount).toBeGreaterThanOrEqual(4); // At least Zeebe, Tasklist, Operate, Optimize
  
  // Verify no error messages are present
  await expect(page.locator('text=/error|failed|invalid|incorrect/i')).not.toBeVisible();
  
  // Additional verification: check that we can interact with the dashboard
  const title = await page.title();
  expect(title).not.toBe('');
  expect(title.toLowerCase()).not.toContain('error');
});
