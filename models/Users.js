const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt');
// const {v4: uuidv4} = require('uuid');
const AutoIncrement = require('mongoose-sequence')(mongoose);

const UserSchema = new Schema({
    id: {
        type: Number,
        unique: true,
        // default: uuidv4   // now we are using auto increment (Mongoose Sequence)
    },
    username: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        match: /^[a-z0-9]+$/   // lowercase and no spaces/special characters
    },
    email: {
        type: String,
        required: true,
        unique: true,
        // lowercase: true,
        // match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    },
    password: {
        type: String,
        required: true,
        minlength: 8
    },
    role: {
        type: String,
        enum: ['user', 'manager', 'owner'],
        default: 'user'
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
}, { timestamps: true });

UserSchema.plugin(AutoIncrement, { inc_field: 'id' });   // auto increment the id field

UserSchema.pre('save', async function (next) {
    // convert username to lowercase if not already
    if (this.username !== this.username.toLowerCase()) {
        this.username = this.username.toLowerCase();
    }

    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }

    next();
});

UserSchema.methods.comparePassword = function (password) {
    return bcrypt.compare(password, this.password);
};

module.exports = mongoose.model('User', UserSchema);