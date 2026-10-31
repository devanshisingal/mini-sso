import { test, expect } from '@playwright/test';
import crypto from 'crypto';

/**
 * RFC 6238 TOTP helper for automated 2FA code generation during E2E tests.
 */
function generateTotpCode(base32Secret: string): string {
  const clean = base32Secret.replace(/[\s=]/g, '').toUpperCase();
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (let i = 0; i < clean.length; i++) {
    const val = alphabet.indexOf(clean.charAt(i));
    bits += val.toString(2).padStart(5, '0');
  }

  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }
  const key = Buffer.from(bytes);

  const epoch = Math.floor(Date.now() / 1000);
  const timeStep = Math.floor(epoch / 30);
  const timeBuffer = Buffer.alloc(8);
  timeBuffer.writeBigInt64BE(BigInt(timeStep));

  const hmac = crypto.createHmac('sha1', key).update(timeBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const codeInt =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = codeInt % 1000000;
  return otp.toString().padStart(6, '0');
}

test.describe('Mini SSO End-to-End Flow', () => {
  test('Complete user registration, TOTP 2FA enrollment, and demo app sign-in', async ({ page }) => {
    const testEmail = `e2e_user_${Date.now()}@example.com`;
    const testPassword = 'Password123!@#';

    // 1. Visit Demo Application
    await page.goto('http://localhost:5174');
    await expect(page.getByText('Demo Client Application')).toBeVisible();

    // 2. Click "Sign in with Mini SSO"
    await page.getByRole('button', { name: /Sign in with Mini SSO/i }).click();

    // 3. Browser is redirected to IdP UI Login Screen
    await expect(page).toHaveURL(/localhost:5173\/login/);
    await expect(page.getByText('Mini SSO Service')).toBeVisible();

    // 4. Navigate to Register
    await page.getByRole('link', { name: /Register here/i }).click();
    await expect(page).toHaveURL(/localhost:5173\/register/);

    // 5. Fill registration form
    await page.locator('#email').fill(testEmail);
    await page.locator('#password').fill(testPassword);
    await page.locator('input[placeholder="Repeat password"]').fill(testPassword);
    await page.getByRole('button', { name: /Register & Continue/i }).click();

    // 6. Redirected to MFA Setup
    await expect(page).toHaveURL(/localhost:5173\/mfa-enroll/);
    await expect(page.getByText('Set Up Authenticator')).toBeVisible();

    // Copy the base32 secret
    const secretInput = page.locator('input[readonly]');
    await expect(secretInput).toBeVisible();
    const secret = await secretInput.inputValue();
    expect(secret.length).toBeGreaterThanOrEqual(16);

    // Generate genuine TOTP code using RFC 6238 algorithm
    const totpCode = generateTotpCode(secret);
    await page.locator('input[placeholder="123456"]').fill(totpCode);
    await page.getByRole('button', { name: /Activate 2FA & Continue/i }).click();

    // 7. IdP completes authorization and redirects browser back to Demo App /callback
    await expect(page).toHaveURL(/localhost:5174/, { timeout: 15000 });

    // 8. Demo App successfully displays authenticated user profile
    await expect(page.getByText(testEmail)).toBeVisible();
    await expect(page.getByText('SSO Authenticated')).toBeVisible();
    await expect(page.getByText('Verified ID Token Claims')).toBeVisible();

    // 9. Sign out
    await page.getByRole('button', { name: /Sign Out/i }).click();
    await expect(page.getByRole('button', { name: /Sign in with Mini SSO/i })).toBeVisible();
  });
});
