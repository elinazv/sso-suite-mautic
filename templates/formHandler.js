$(document).ready(function() {
    console.log('doc');
    // validate the comment form when it is submitted
    //$("#commentForm").validate();

    //custom validation rule
    $.validator.addMethod("customemail",
        function(value, element) {
            //return /^([a-zA-Z0-9_.-+])+\@(([a-zA-Z0-9-])+.)+([a-zA-Z0-9]{2,4})+$/.test(value);
            var re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

            var check = re.test(String(value).toLowerCase());

            console.log('check: ' + check);
            return check;
        },
        "Sorry, I've enabled very strict email validation"
    );

    $.validator.addMethod("checklower", function(value) {
        return /[a-z]/.test(value);
    });
    $.validator.addMethod("checkupper", function(value) {
        return /[A-Z]/.test(value);
    });
    $.validator.addMethod("checkdigit", function(value) {
        return /[0-9]/.test(value);
    });

    // validate signup form on keyup and submit
    $("#contactForm").validate({
        errorClass: "error",
        errorElement: "span",
        rules: {
            //firstname: "required",
            lastname: {
                required: true,
                minlength: 2
            },
            username: {
                required: true,
                minlength: 5
            },
            password: {
                required: true,
                minlength: 6,
                checklower: true,
                checkupper: true,
                checkdigit: true
            },
            email: {
                required: true,
                customemail: true
            },
            firstname: {
                required: true,
                minlength: 2
            }
        },
        messages: {
            firstname: "Please enter your first name",
            lastname: "Please enter your last name",
            username: {
                required: "Please enter a username",
                minlength: "Your username must consist of at least 6 characters"
            },
            password: {
                required: "Please provide a password",
                minlength: "Your password must be at least 5 characters long",
                checklower: "Need at least 1 lowercase alphabet",
                checkupper: "Need at least 1 uppercase alphabet",
                checkdigit: "Need at least 1 digit"
            },
            email: "Please enter a valid email address",

        },
        highlight: function(element, errorClass) {
            var parentDiv = element.parentElement;
            parentDiv.classList.add("errorDiv");
        },
        submitHandler:function(form) {
           // $(form).ajaxSubmit();
           // alert('submitHandler');
            startLoading();
            jsonpCall()
                .done(function(data) {
                    console.log(data);
                    if (typeof data.error != 'undefined' && data.error == true){
                        stopLoading();
                        showErrorContainer();
                    } else {
                        jsonpCall1().done(function(data) {
                            console.log('lala1');
                            console.log(data);
                            input = input + '&mautic_id_c=' + data.mautic_id_c;
                            if (typeof data.error != 'undefined' && data.error == true){
                                stopLoading();
                                showErrorContainer();
                            } else {
                                jsonpCall2().done(function(data) {
                                    console.log('lala2');

                                    stopLoading();

                                    console.log(data);
                                    if (typeof data.error != 'undefined' && data.error == true){
                                        showErrorContainer();
                                    } else {

                                        window.location.href = '/success';
                                    }
                                }).fail(function() {
                                        alert("Your third API call blew it.");
                                    }

                                );
                                //alert(data);

                            }
                        }).fail(function(error) {
                            console.log(error);
                            alert("Your second API call blew it.");
                        });
                    }
                }).fail(function(data) {
                    console.log(data);
                alert("Your first API call blew it.");
            });
        }
    });

});


function displayPayload(response) {
    $(".target-div").html(response.payload);
}

function display(message) {
    console.log('dis');
   alert(message);
}
var input;
function jsonpCall() {
    console.log('jp');

    input = $("#contactForm").serialize();
    console.log(input);
    return $.ajax({
        url: "/create",
        type: "POST",
        data: input,
        timeout: 30000
    });
}

function jsonpCall1() {
    console.log('jp1');
    /*var input;
    input = $("#contactForm").serialize();*/
    console.log(input);
    return $.ajax({
        url: "/mautic",
        type: "POST",
        data: input,
        timeout: 30000
    });
}

function jsonpCall2() {
    console.log('jp2');
    /*var input;
    input = $("#contactForm").serialize();*/
    console.log(input);
    return $.ajax({
        url: "/suite",
        type: "POST",
        data: input,
        timeout: 30000
    });
}



