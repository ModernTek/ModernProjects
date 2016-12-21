/***************************************************************************************
 *             Validation rules for credit/debit form.
 *
 *  The user's name:    User's input is at least 5 characters long.
 *  The expired date:   User's input is correct date and after today date.
 *  Card number:        User's input is a valid credit card number.
 *  CVV number:         User's input is a valid cvv number.
 **************************************************************************************/ 
(function() {
  var card_name    = document.getElementById('card_name');
  var card_number  = document.getElementById('card_number');
  var card_expiry  = document.getElementById('card_expiry'); 
  var expDate      = card_expiry.value.split('-');
  var card_cvv     = document.getElementById('cvv');
  var credit_debit = document.getElementById('credit_debit_form');
  
  var checkCardNameValidity = function(){
    if (!(validator.isOfLength(card_name.value,5))){
      card_name.setCustomValidity(' Name on the card must be at least 5 characters long.');     
    }else{
      card_name.setCustomValidity('');
    }
  };
  var checkCardNumberValidity = function(){
    if (!(validator.isCreditCard(card_number.value))){
      card_number.setCustomValidity('Only numbers and capital letters, split with a hyphen into four groups of four characters. You can also enter complete number without hyphens.');
    }else{
      card_number.setCustomValidity('');
    }
  };
  var checkExpiryDateValidity = function()  {
    var expDate = card_expiry.value.split('-');
    if (!(validator.isAfterToday(new Date(expDate[0], expDate[1], 0)) ) ){
      card_expiry.setCustomValidity('Expiration Date must be after today');
    }else{
      card_expiry.setCustomValidity('');
    }
  };
  var checkCvvNumberValidity = function() {
    var char; var valid=true;
    /* cvv number */
    for (var i = 0, l = card_cvv.value.length; i < l; i++) {
      char = card_cvv.value.charCodeAt(i);
      if (char < 48 || char > 57) {
        valid = false;
      }
    }
     if (!valid){
      card_cvv.setCustomValidity('Did you enter three digit code from the back of your credit card?');
    }else if (valid){
      card_cvv.setCustomValidity('');
    }  
    
  }; 
 
  /*add listeners to all inputs on the form  */
  card_name.addEventListener('change', checkCardNameValidity, false);
  card_number.addEventListener('change', checkCardNumberValidity, false);
  card_expiry.addEventListener('change', checkExpiryDateValidity, false);
  card_cvv.addEventListener('change', checkCvvNumberValidity, false);
  
  /* add event listenr to creditdebit form */
  credit_debit.addEventListener('submit', function(event) {
    event.preventDefault();
  })    
 
}());



    
   
