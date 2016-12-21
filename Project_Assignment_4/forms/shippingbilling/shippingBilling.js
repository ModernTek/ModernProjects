/****************************************************************************************
 *             Validation rules for shipping billing form.                              * 
 * The user's first name:    User's input is not empty and that it is as least a length * 
 *                            two characters.                                           *
 *  The user's last name:     User's input is not empty and that it is as least a length*
 *                            two characters.                                           *
 *  The user's email address: User's input is not empty and that it is a valid email    *
 *                            address.                                                  *
 *  The user's date of birth: User's birthday is before today.                          *
 *  The user's home pnone:    User's input is not empty and that it is a valid number   *
 *  for USA.                                                                            *
 *  The user's work pnone:    User's input is not empty and that it is a valid number   *
 *  for USA.                                                                            *
 ****************************************************************************************/
(function(){
  var shippingBilling =
      document.getElementById("shipping_billing_form");
  shippingBilling.addEventListener('submit', function(event) {    
      event.preventDefault();
    })
 
   var phoneMsg = "Please eneter valid work number  in this " + "format 1-xxx-123-0555 where 1 is code country" +                                      "xxx-area code";
  shippingBilling.addEventListener('change', function(event) {
     var eventTarget = event.target;
     console.log("event.target.className=" +event.target.className);
     if (eventTarget == this) {
    } else {
       var input = event.target;
       var id = input.getAttribute("id");
       var inputText = input.value;
       switch(id){
        case "firstS":
          if (inputText.length < 5) {
            input.setCustomValidity("First name must be at least 5 characters long");
          } else{
            input.setCustomValidity('');
          } 
          break;
        case "lastS": 
          if (inputText.length < 5) {
            input.setCustomValidity("Last name must be at least 5 characters long");                                   
          } else{
            input.setCustomValidity('');
          } 
          break;
        case "homeTelS":
           
          if (!(validator.isPhoneNumber(inputText))){
            
            input.setCustomValidity(phoneMsg);
          }else{
             
             input.setCustomValidity('');
    
          }
          break;
        case "workTelS":
          if (!(validator.isPhoneNumber(inputText))){
            input.setCustomValidity(phoneMsg);
          }else{
            input.setCustomValidity('');
    
          }
          break;
          
          case "stateS":
            var char;
            // assume valid unless test fails
            var valid = true;
     
            if (inputText.length == 2){
              //Make sure that each character is alpha
              var i = 0;
              while (valid && i < inputText.length)  { 
              
                char = inputText.charCodeAt(i);
                 
                if (!(char > 64 && char < 91)  &&  // upper alpha (A-Z)
                    !(char > 96 && char < 123)){   // lower alpha (a-z) 
                  valid = false;
                }
                i++;
              } //while loop
            }else{
              valid = false;
            } 
            break;
          case "zipS":
            var char;
             // assume valid unless test fails
            var valid = true;
             
            if (inputText.length === 5) {
        
                // make sure each character is a digit
              var i=0;
              while(valid && i<inputText.length)  {
                
                char = inputText.charCodeAt(i);
                 
                if (!(char > 47 && char < 58)){  
                   
                   valid = false;
           
                }
                i++;
              }//while loop
            } else {
               valid = false;
            }
            if (!valid){
              input.setCustomValidity("Zip code must be five characters long and" + "must have only numeric characters");
            }else{
              input.setCustomValidity('');
            }
            break;
           case "cityS":
             if (inputText.length < 3){
               input.setCustomValidity("City name must be at least three characters long");
             }else{
               input.setCustomValidity('');
             }
           break;
         } /* end case statement */
       } /* event target this */   
  }) /* shippingBilling add eventListener on change */ 
 
}());


    
   

  
    

   
 
