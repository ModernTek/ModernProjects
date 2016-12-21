(function() {
  var questionForm = document.getElementById('question_form');
  var iceCream = document.getElementById('iceCreamV');
  var other = document.getElementById('other');
  
  //Check Validity
  var checkQuestionnarieValidity = function(){
    console.log("validate");
    var radios =
    questionForm.querySelectorAll('input[type="radio"]:checked');
    
    if (radios.length > 0){
      //Check if other radio button is selected
      if (other.checked == true) {
        
        var others = document.getElementById("others");
        
        //Check if value of text "other" is not empty
        if (!validator.isEmpty(others.value)){
          others.setCustomValidity('');              
        }else{
          iceCream.setCustomValidity('');       
          others.setCustomValidity("Please explain what ice cream you would like");
        
        }/* field others is wrong */
      } else {        
        iceCream.setCustomValidity('');
      }
    }else{
      // radio button not selected      
      iceCream.setCustomValidity("Please choose your favorite ice cream");
    }  
  };
  questionForm.addEventListener('click', checkQuestionnarieValidity, false); 
  questionForm.addEventListener('submit', function(event){
    event.preventDefault();
      
  })

}())
