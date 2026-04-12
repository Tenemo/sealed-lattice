import { describe, expect, it } from 'vitest';

describe('browser mobile runtime', () => {
    it('runs in a mobile-emulated context', () => {
        expect(navigator.userAgent).toContain('Mobile');
        expect(window.innerWidth).toBeLessThanOrEqual(430);
    });
});
