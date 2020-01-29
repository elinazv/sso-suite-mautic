//alert('hurra');
function testLoading()
{
    alert('testLoading');

    startLoading();

    setTimeout(function(){
            alert("Hello");
            stopLoading();
        },
        3000);
}

function startLoading()
{
    document.getElementById('loaderEnclosing').style.zIndex = '999999';
    document.getElementById('loaderEnclosing').style.visibility = 'visible';
}

function stopLoading()
{
    document.getElementById('loaderEnclosing').style.zIndex = '-1';
    document.getElementById('loaderEnclosing').style.visibility = 'hidden';
}

function showErrorContainer()
{
    document.getElementById('errorContainer').style.visibility = 'visible';
}