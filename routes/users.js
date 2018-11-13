var express = require('express');
var router = express.Router();

//引入crypto模块
var md5 = require("crypto");

// 引入数据库链接模块
var connection = require("./mysqlConn");

//添加用户的路由
router.post('/add', function (req,res,next) {
  //2 后端路由接收前端数据
  let {pass,username,region} = req.body;
  //对密码进行MD5加密
  pass = md5.createHash("md5").update(pass).digest("hex");

  //3. 链接数据库 补数据写入数据库
  //定义sql语句
  let sqlStr = "insert into userTable(userName,userPwd,userGroup) values(?,?,?)";
  let sqlParams = [username,pass,region];
  //执行sql语句
  connection.query(sqlStr,sqlParams, function (error,results) {
    if(error) throw error; //出错对象

    //根据执行sql语句的结果返回json给前端
    if (results.affectedRows > 0) {
      res.send({"isOk":true,"msg":"账号添加成功!"});
    } else {
      res.send({"isOk":false,"msg":"账号添加失败!"})
    }
  });
});


//获取用户列表路由
router.get("/list",(req,res)=>{
  //1 构造sql语句
  let sqlStr = "select * from userTable order by u_id DESC";

  //2 执行sql语句
  connection.query(sqlStr, function (error,userlist) {
    if (error) throw error;
    //3 返回查询结果到前端
    res.send(userlist);
  });
});

// 删除用户的路由
router.get("/del",(req,res)=>{
  //3. 后端路由接收删除的id 返回结果到前端
  let id=req.query.id;

  //构造sql语句
  let sqlStr="delete from userTable where u_id=?";
  let sqlParams=[id];

  //执行删除sql
  connection.query(sqlStr,sqlParams,(error,result)=>{
    if(error) throw error;
    //"affectedRows":1, 返回受影响的行数，如果大于0就表示成功
    if(result.affectedRows>0){
      res.send({"isOk":true,"msg":"账号删除成功!"});
      //res.redirect("member_list.html");  后端没有分离的做法【不推荐】
    }
    else{
      res.send({"isOk":false,"msg":"账号删除失败!"});
    }
  });
});


// 根据id获取用户数据的路由
router.get("/getUserByID",(req,res)=>{
 //1. 接收用户id
 let id=req.query.id;
 
 //2. 构造sql语句
 let sqlStr="select * from userTable where u_id=?";
 let sqlParams=[id];

 //3. 执行sql语句
 connection.query(sqlStr,sqlParams,function (error,userData) {
   if (error) throw error; //出错后面的代码不执行
   //4. 返回查询的结果到前端（对象数组）
   res.send(userData);
 });
});

//3）接收新的数据并把新的数据update到数据库中
router.post('/save', function(req, res, next) {
 //2. 后端路由接收前端的数据
 let {pass,username,region,u_id,oldPwd}=req.body;
 let newPass=pass; //只是为了名字更醒目

 //对新旧密码进行比较，如果不等就密码已修改，对新的密码进行md5加密
 if(oldPwd!=newPass){
   pass=md5.createHash("md5").update(newPass).digest("hex");
 }

 //3. 链接数据库，把数据库写入数据库
 //定义sql语句;
 let sqlStr="update userTable set userName=?,userPwd=?,userGroup=? where u_id=?"; //占位符
 let sqlParams=[username,pass,region,u_id]; //参数数组
 //执行sql语句
 connection.query(sqlStr,sqlParams, function (error, results) {
   if (error) throw error; //出错对象
   //4. 返回处理的结果到前端
   //根据执行sql语句的结果返回json给前端
   if(results.affectedRows>0){
     res.send({"isOk":true,"msg":"账号修改成功!"});
   }
   else{
     res.send({"isOk":false,"msg":"账号修改失败!"});
   }
 });
});

//验证用户是否是合法登录的路由
router.post("/loginCheck",(req,res,next)=>{
  //2 后端路由接收前端传入的用户名和密码，并根据用户名和密码做数据库查询
  let {username,checkPass} = req.body;
  let sqlStr = "select u_id from userTable where userName=? and userPwd=?";
  //对密码进行md5加密
  checkPass = md5.createHash("md5").update(checkPass).digest("hex");
  let sqlParams = [username,checkPass];

  //3 后端如果查询到结果说明成功 否则就失败 验证登录成功写入cookie
  connection.query(sqlStr,sqlParams,function (err,result) {
    if(err) throw err;
    //如果result是空数组说明用户名或者密码不正确 如果不是空就合法
    if(result.length > 0) {
      //登录成功就写入cookie
      res.cookie("username",username);
      res.cookie("u_id",result[0].u_id);
      res.send({isOk:true,msg:"用户登录成功!"});
    } else {
      res.send({isOk:false,msg:"用户登录失败!"})
    }
  })
});


// 退出登录就销毁cookie
router.get("/sigOut",(req,res)=>{
  //清除cookie
  res.clearCookie("username");
  res.clearCookie("u_id");
  //跳转到登录页面
  res.redirect("/signin.html");
});

//验证身份的合法性 有cookie合法  没有cookie不合法
router.get("/checkState",(req,res)=>{
  //读取cookie
  var username = req.cookies.username;

  //用户名不存在就是非法就跳转到登录页面
  if(!username){
    res.send("alert('非法入侵，请登录!');location.href = 'signin.html';");
  } else {
    res.send("");
  }
})


module.exports = router;
