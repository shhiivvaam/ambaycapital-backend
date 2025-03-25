const request = require('supertest');
const app = require('../server');

describe('GET /health', () => {
    it('should respond with health data', async () => {
        const response = await request(app).get('/');
        expect(response.status).toBe(200);
        expect(response.body).toHaveProperty('title', 'Ambay Capital');
    });
});