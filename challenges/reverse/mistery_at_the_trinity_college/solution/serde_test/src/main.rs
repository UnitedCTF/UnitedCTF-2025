use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Msg1 {}

fn step_1(datas: &Vec<&str>) {
    println!("step_1");
    for data in datas {
        _ = serde_json::from_str::<Msg1>(data).inspect_err(|x| {
            println!("{data} - {x}");
        });
    }
}

#[derive(Serialize, Deserialize)]
struct Msg2 {
    a: String,
}

fn step_2(datas: &Vec<&str>) {
    println!("step_2");
    for data in datas {
        _ = serde_json::from_str::<Msg2>(data).inspect_err(|x| {
            println!("{data} - {x}");
        });
    }
}

#[derive(Serialize, Deserialize)]
enum Variant1 {
    A,
}

#[derive(Serialize, Deserialize)]
struct Msg3 {
    a: Variant1,
}

fn step_3(datas: &Vec<&str>) {
    println!("step_3");
    for data in datas {
        _ = serde_json::from_str::<Msg3>(data).inspect_err(|x| {
            println!("{data} - {x}");
        });
    }
}

#[derive(Serialize, Deserialize)]
enum Variant2 {
    A(String),
}

#[derive(Serialize, Deserialize)]
struct Msg4 {
    a: Variant2,
}

fn step_4(datas: &Vec<&str>) {
    println!("step_4");
    for data in datas {
        _ = serde_json::from_str::<Msg4>(data).inspect_err(|x| {
            println!("{data} - {x}");
        });
    }
}

fn main() {
    let datas = vec![
        "{}",
        r#"{"a":"ahbsjkd"}"#,
        r#"{"a":"A"}"#,
        r#"{"a":{"A":"asd"}}"#,
    ];

    step_1(&datas);

    step_2(&datas);

    step_3(&datas);

    step_4(&datas);
}
