const express =  require('express');
const router = express.Router();

const authRoutes = require('./authRoutes');

// health check
const user = {
    author: "Rajesh Kumar",
    date: new Date().toISOString().split('T')[0],
    title: "Ambay Capital",
    description: "Your Insurance Advisor and Financial Planner",
    web: "https://ambaycapital.netlify.app",
    companyAvatar: "https://avatars.githubusercontent.com/u/193356097?s=400&u=8b1f1c830d35bf45c802da26dc1650f3bc714b3d&v=4",
    slug: "insurance_investment_savings",
};
router.get('/', (req, res) => res.send(user));

router.use('/api/auth', authRoutes);

module.exports = router;