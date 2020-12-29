

const requireLogin = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        res.redirect('/unauthorized');
    }
};

const logout = (req, res) => {
    console.log('logging out...');
    req.session.destroy(() => {
        // After deleting session:
        res.redirect('/');
    });
};
module.exports = {
    requireLogin,
    logout
};
