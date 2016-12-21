/***********************************************************************
*                 Validation rules for login page.                     *
*                                                                      *
* Check if user's input "User name" is not empty and length            *
* is at least two characters long.                                     *
* Check if user's' input "Password" is not empty and length            *
* at least eight characters long.                                      *
* Check is user's input "Confirm password is not empty, at least       *
* eight characters long and the same as User entered field "Password". *
/***********************************************************************/
(function(){
  var loginPage = document.getElementById('login_page');
  var password = '';
  loginPage.addEventListener('change', function(event){
    var eventTarget = event.target;
    console.log("event.target.className =" + event.target.className);
    if (eventTarget == this) {
      console.log(eventTarget);
    } else {
      var input = event.target;
      var id = input.getAttribute("id");
      var inputText = input.value;
      switch(id){
        case "userName":
          if (inputText.length < 5){
            input.setCustomValidity("User name must be at least 5 characters long");
          } else{
            input.setCustomValidity('');
          } 
        break;
        case "password":
          if (inputText.length < 8){
            input.setCustomValidity("Password must be at least 8 characters long");
          }else{
            input.setCustomValidity('');
            password = inputText;
          } 
        break;                      
        case "confirm_password":
          if (inputText != password){
            input.setCustomValidity("Passwords should match");
          }else{
            input.setCustomValidity('');
              
          } 
        break;
        default:
          console.log("nothing changed");            
      }             
    }
})
  loginPage.addEventListener('submit', function(event){
    event.preventDefault();
  })
}());
 
