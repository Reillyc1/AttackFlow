var signup = new Vue({
    el: '#vue_signup',
    data: {
        username: "",
        email: "",
        password: "",

        // Validation messages
        username_message: "",
        email_message: "",
        password_message: "",

        disabled: true,
    },

    methods: {
        // validateUsername: function() {
        //     if (this.username.length > 64) {
        //         this.username_message = "Username must be 64 characters or less.";
        //         this.username = this.username.slice(0, 64);
        //     } else {
        //         this.username_message = "";
        //     }
        // },
        // validateEmail: function() {
        //     if (this.email.length > 64) {
        //         this.email_message = "Email must be 64 characters or less.";
        //         this.email = this.email.slice(0, 64);
        //     } else {
        //         this.email_message = "";
        //     }
        // },
        // validatePassword: function() {
        //     if (this.password.length > 128) {
        //         this.password_message = "Password must be 128 characters or less.";
        //         this.password = this.password.slice(0, 128);
        //     } else {
        //         this.password_message = "";
        //     }
        // },
        onClickUserSignUpManual: function() {
            if (this.password.length < 8) {
                this.password_message = "Password must be at least 8 characters long.";
            }
            if (this.username === '') {
                this.username_message = "Username cannot be blank.";
            }
            if (this.email === '') {
                this.email_message = "Email cannot be blank.";
            }
            if (this.password === '') {
                this.password_message = "Password cannot be blank.";
            } else {
                this.disabled = false;
                console.log("signup");
                //sign up user here
                let user_data = {name: this.username,
                                email: this.email,
                                password: this.password};

                // Create new AJAX request
                var xhttp = new XMLHttpRequest();
                // Open connection
                xhttp.open("POST", "/signUp", true);
                // Set content type to JSON
                xhttp.setRequestHeader("Content-type","application/json");
                // Send request
                xhttp.send(JSON.stringify(user_data));

                // Handle response
                xhttp.onreadystatechange = function() {
                    if (this.readyState == 4 && this.status == 200) {
                        // Functions once emails have been sent
                        location.assign('/user');
                    }
                };
            }
        }
    }
})