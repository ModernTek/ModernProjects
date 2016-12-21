/****************************************************************************************
 *             Validation rules for signup form.                                        *
 *  THe user's first name:    User's input is not empty and that it is as least a length*
 *                            five characters.                                          *
 *  The user's last name:     User's input is not empty and that it is as least a length*
 *                            five characters.                                          *
 *  The user's email address: User's input is not empty and that it is a valid email    *
 *                            address.                                                  *
 *  The user's date of birth: User's birthday is before today.                          *
 *  The user's home pnone:    User's input is not empty and that it is a valid number   *
 *  for USA.                                                                            *
 *  The user's work pnone:    User's input is not empty and that it is a valid number   *
 *  for USA.                                                                            * 
 ************************************************************************************** */
(function() {
  var signupForm =
                  document.getElementById('signup_form');
  // Get first name value
  var first = document.getElementById('first'); 
  //console.log("first " + first.value);
  //Get last name value      
  var last = document.getElementById('last');  
  // Get email value
  var  email = document.getElementById('email');
        
  //Get Date of Birth value
  var dob = document.getElementById('dob');
  var phoneHome = document.getElementById('home_tel');
  var phoneWork = document.getElementById('work_tel');
  var street = document.getElementById('street');
  var city = document.getElementById('city');
  var state = document.getElementById('state');
  var zip_code = document.getElementById('zip_code');
  
  /******************************* CheckValidity functions ************************************/
  /* First Name */
   var checkFirstNameValidity = function(){
     
     if (first.value.length < 5){
      
       first.setCustomValidity(' First name must be at least 5 characters long.');     
      }else{
        first.setCustomValidity('');
     }
  };
  /* Last Name */
   var checkLastNameValidity = function(){
    if (last.value.length < 5){
      
      last.setCustomValidity('Last name must be at least 5 characters long');     
    }else{
      last.setCustomValidity('');
    }
   
  };
 
   /* dob */
   var checkDOBValidity = function(){
     
    if (!(validator.isBeforeToday(dob.value))){
      dob.setCustomValidity('Date Of Birth should before today date.');     
    }else{
      dob.setCustomValidity('');
    }
  };
   /* phoneHome */
   var checkPhoneHomeValidity = function(){
    if (!(validator.isPhoneNumber(phoneHome.value))){
      phoneHome.setCustomValidity('Please enter valid home phone number  in this format 1-xxx-123-0555 where 1 is code country, xxx-area code.');     
    }else{
      phoneHome.setCustomValidity('');
    }
     
  };
  /* phoneWork */
   var checkPhoneWorkValidity = function(){
    if (!(validator.isPhoneNumber(phoneWork.value))){
      phoneWork.setCustomValidity('Please enter valid work phone number  in this format 1-xxx-123-0555 where 1 is code country, xxx-area code.');     
    }else{
      phoneWork.setCustomValidity('');
    }
  };
  /* street address */ 
  var checkStreetValidity = function(){
    
    if ((street.value.length < 3) || (!validator.isAlphanumeric(street.value))){
      street.setCustomValidity('Street name must be at least three characters long and consist of only alpha numeric characters');
    }else{
      street.setCustomValididty('');
    }
    
  };
  /* zip code */
  var checkZipCodeValidity = function(){
    var char;
    
    var valid = true;
             
    if (zip_code.value.length === 5) {
        
      // make sure each character is a digit
      var i=0;
      while(valid && i<zip_code.value.length)  {
                
        char = zip_code.value.charCodeAt(i);
                 
        if (!(char > 47 && char < 58)){  
                   
          valid = false;
           
        }
        i++;
      }//while loop
    } else {
      valid = false;
    }
    if (!valid){
 
      zip_code.setCustomValidity("Zip code must be five characters long and " +            
                                  "must have only numeric characters");
    }else{
      zip_code.setCustomValidity('');
    }
  };
  /* state */
  var checkStateValidity = function(){
    var char;
    // assume valid unless test fails
    var valid = true;
    if (state.value.length == 2){
      //Make sure that each character is alpha
      var i = 0;
      while (valid && i < state.value.length)  { 
              
        char = state.value.charCodeAt(i);
                 
        if (!(char > 64 && char < 91)  &&  // upper alpha (A-Z)
			      !(char > 96 && char < 123)){   // lower alpha (a-z) 
           valid = false;
        }
        i++;
      } //while loop
    }else{
      valid = false;
    } 
    if (!valid){
      state.setCustomValidity("State code must be two characters long " +
                              "and must consist of only aplha characters");
    }else{
      state.setCustomValidity('');
    } 
  };
  /* city */
  var checkCityValidity = function(){
    
    if ((city.value.length < 3) || (!validator.isAlphanumeric(city.value))){
      city.setCustomValidity('Street name must be at least three charaters long and consist of only alpha numeric characters');
    }else{
      city.setCustomValididty('');
    }
    
  };
     
  /*add listeners to all inputs on the form  */
  first.addEventListener('change', checkFirstNameValidity, false);
  last.addEventListener('change', checkLastNameValidity, false);
  dob.addEventListener('change', checkDOBValidity, false);
  phoneHome.addEventListener('change', checkPhoneHomeValidity, false);
  phoneWork.addEventListener('change', checkPhoneWorkValidity, false);
  street.addEventListener('change', checkStreetValidity, false);
  city.addEventListener('change', checkCityValidity, false);
  state.addEventListener('change', checkStateValidity, false);
  zip_code.addEventListener('change', checkZipCodeValidity, false);
  
   /* add submit event listenr to signup form */
  signupForm.addEventListener('submit', function(event) {
      event.preventDefault();   
  })
  
}());
