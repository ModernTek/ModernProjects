/***************************************************************************************
 *             Validation rules for scheduling form.                                   *
 *                                                                                     *
 *  The user's email address: User's input is not empty and that it is a valid email   * 
 *                            address.                                                 *
 *  The appointment's date :  Appointment's day & time are after today.                *
 *  The user's home pnone:    User's input is not empty and that it is a valid Phone   *
 *  nuber for USA.                                                                     * 
 *  The user's work pnone:    User's input is not empty and that it is a valid number  *
 *  for USA.                                                                           *
 *                                                                                     *
 **************************************************************************************/
(function() {
   var scheduleAppt = document.getElementById("schedule_appt");
     
    var apptDate = document.getElementById('date');
     
    var apptTime = document.getElementById('time');
    
   //Message if not valid email
    var  emailAddress = document.getElementById("email");
      
    //Message if not valid phone
    //Get home phone number   
    var phoneHome = document.getElementById("home_tel"); 
     
    //Message if not valid phone
    //Get work phone number   
    var phoneWork = document.getElementById("work_tel");

    var newTime = function() {
    //Grab the time and split into hrs and mins
      
	  var time = document.getElementById("time");
	  var hrs = time.value.split(":")[0];
    var mins = time.value.split(":")[1];
    var newTime = ampm(hrs, mins);
      
};

function ampm(hrs, mins) {
   return ( hrs % 12 || 12 ) + ":" + mins + (( hrs >= 12 ) ? "PM" : "AM" );
}
  
    var checkDateTimeValidity = function(){  
      if (!validator.isAfterToday(apptDate.value) ) {
        apptDate.setCustomValidity("Appointment Date must be after today");
      }else{
           apptDate.setCustomValidity('');
      } 
    };
     
 
   //Function to check Home Phone Validity
   var checkPhoneHomeValidity = function(){
     if (!(validator.isPhoneNumber(phoneHome.value)) ) {
       phoneHome.setCustomValidity("Phohe home number is not valid");
     }else{    
       phoneHome.setCustomValidity('');
     }
   }; 
 
   //Function to check Work Phone Validity
   var checkPhoneWorkValidity = function(){
  
     if (!(validator.isPhoneNumber(phoneWork.value)) ){
       phoneWork.setCustomValidity("Phone work number is not valid");
     }else{
       phoneWork.setCustomValidity('');
     }
   }; 
   /*add listeners to all inputs on the form  */
  apptTime.addEventListener('change', newTime, false);
  apptDate.addEventListener('change', checkDateTimeValidity, false);
  phoneHome.addEventListener('change', checkPhoneHomeValidity, false);
  phoneWork.addEventListener('change', checkPhoneWorkValidity, false);
  
  /* add event listenr to schedule form */
  scheduleAppt.addEventListener('submit', function(event) {
      event.preventDefault();
  }) 

}());
