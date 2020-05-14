async fn tomikod() -> Option<()> {
    
    Some(())
}

#[tokio::main]
async fn main() -> Result<(), ()> {
    tomikod()
	.await
	.ok_or(())
}
